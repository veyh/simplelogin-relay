use anyhow::{bail, Result};
use config::Config;
use lettre::address::{Address, Envelope};
use mailin_embedded::{AuthMechanism, Handler, Server, SslConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use simplelogin_relay::api::*;
use simplelogin_relay::mailer::*;
use simplelogin_relay::settings::{Account, Settings};
use simplelogin_relay::types::*;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simplelogin_relay=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let settings = Arc::new(parse_settings().unwrap());

    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .https_only(true)
        .build();

    // NOTE: Cloned for each connection.
    let handler = HandlerImpl {
        settings: settings.clone(),
        api: Arc::new(ApiImpl {
            agent,
            settings: settings.clone(),
        }),
        mailer: Arc::new(MailerImpl::new(&settings)?),
        data: vec![],
        account: None,
        reverse_alias: None,
        recipient_email: None,
        recipients: HashMap::new(),
    };

    let mut server = Server::new(handler);
    let addr = format!("{}:{}", settings.host, settings.port);

    server
        .with_name(&settings.name)
        .with_ssl(SslConfig::SelfSigned {
            cert_path: settings.cert_path.clone(),
            key_path: settings.key_path.clone(),
        })
        .unwrap()
        .with_addr(&addr)
        .unwrap()
        .with_auth(AuthMechanism::Plain)
        .with_num_threads(1);

    debug!(addr, "serving");

    server.serve().unwrap();
    Ok(())
}

fn parse_settings() -> Result<Settings> {
    let settings_raw = Config::builder()
        .add_source(config::File::with_name("config"))
        .add_source(config::Environment::with_prefix("SIMPLELOGIN_RELAY"))
        .build()
        .unwrap();

    let Ok(settings) = settings_raw.try_deserialize() else {
        bail!("failed to deserialize");
    };

    Ok(settings)
}

#[derive(Clone)]
struct HandlerImpl {
    settings: Arc<Settings>,
    api: Arc<dyn Api>,
    mailer: Arc<dyn Mailer>,

    data: Vec<u8>,
    account: Option<Account>,

    recipient_email: Option<String>,
    reverse_alias: Option<ReverseAlias>,

    recipients: HashMap<String, Option<ReverseAlias>>,
}

impl HandlerImpl {
    fn on_data_end(&mut self) -> Result<()> {
        if self.account.is_none() {
            bail!("no account --> exit");
        }

        self.ensure_reverse_alias()?;
        self.modify_headers()?;
        self.send_mail()?;

        let data_str = String::from_utf8_lossy(&self.data);
        debug!("data_str: {:?}", data_str);
        // println!("{}", data_str);

        Ok(())
    }

    fn ensure_reverse_alias(&mut self) -> Result<()> {
        debug!("ensure_reverse_alias");

        let alias_id = self.find_alias_id()?;
        self.reverse_alias = Some(self.create_reverse_alias(alias_id)?);

        for (email, reverse_alias) in self.recipients.iter_mut() {
            *reverse_alias =
                Some(self.api.create_reverse_alias(alias_id, email)?);
        }

        Ok(())
    }

    fn find_alias_id(&self) -> Result<u64> {
        let Some(ref account) = self.account else {
            bail!("no account");
        };

        self.api.find_alias_id(account)
    }

    fn create_reverse_alias(&self, alias_id: u64) -> Result<ReverseAlias> {
        let Some(recipient_email) = &self.recipient_email else {
            bail!("no recipient email");
        };

        self.api.create_reverse_alias(alias_id, recipient_email)
    }

    fn modify_headers(&mut self) -> Result<()> {
        debug!("modify_headers");

        let Some(ref account) = self.account else {
            bail!("no account");
        };

        let mut new_data: Vec<u8> = vec![];
        let mut to_replaced = false;
        let mut from_replaced = false;
        let mut cc_replaced = false;
        let lines = self.data.split_inclusive(|x| *x == b'\n');

        for line in lines {
            match String::from_utf8(line.to_vec()) {
                Ok(s)
                if s.to_lowercase().starts_with("from:")
                && !from_replaced => {
                    let header = format!("From: {}\r\n", account.owner);
                    new_data.append(&mut header.as_bytes().to_vec());
                    from_replaced = true;

                    debug!(old = ?s, new = ?header, "replace")
                }

                Ok(s)
                if s.to_lowercase().starts_with("to:")
                && !to_replaced => {
                    let header = self.replace_dst_header(&s)?;
                    debug!(old = ?s, new = ?header, "replace");

                    new_data.append(&mut header.into_bytes());
                    to_replaced = true;

                }

                Ok(s)
                if s.to_lowercase().starts_with("cc:")
                && !cc_replaced => {
                    let header = self.replace_dst_header(&s)?;
                    debug!(old = ?s, new = ?header, "replace");

                    new_data.append(&mut header.into_bytes());
                    cc_replaced = true;
                }

                _ => {
                    new_data.append(&mut line.to_vec());
                }
            }
        }

        if !to_replaced {
            bail!("not replaced: to");
        }

        if !from_replaced {
            bail!("not replaced: from");
        }

        self.data = new_data;
        Ok(())
    }

    fn replace_dst_header(&self, header: &str) -> Result<String> {
        let mut result = String::new();

        let Some((header_name, recipients)) = header.split_once(':') else {
            bail!("bad header: {:?}", header);
        };

        result.push_str(header_name);
        result.push_str(": ");

        let mut new_recipients: Vec<String> = vec![];

        for recipient in recipients.split(',').map(|x| x.trim()) {
            let left_bracket = recipient.find('<');
            let right_bracket = recipient.find('>');

            if left_bracket.is_some() && right_bracket.is_some() {
                // "Foo Bar" <foo@bar.com>
                // <foo@bar.com>

                let mut new_recipient =
                    recipient[0 .. left_bracket.unwrap()].to_string();

                let email = &recipient[
                    (left_bracket.unwrap() + 1) .. right_bracket.unwrap()
                ];

                let Some(Some(ra)) = self.recipients.get(email) else {
                    bail!("missing reverse alias for {:?}", email);
                };

                new_recipient.push('<');
                new_recipient.push_str(&ra.address);
                new_recipient.push('>');

                new_recipients.push(new_recipient);
            }

            else if left_bracket.is_none() && right_bracket.is_none() {
                let email = recipient;
                let Some(Some(ra)) = self.recipients.get(email) else {
                    bail!("missing reverse alias for {:?}", email);
                };

                new_recipients.push(ra.address.clone());
            }

            else {
                bail!("invalid recipient: {:?}", recipient);
            }
        }

        result.push_str(&new_recipients.join(", "));
        result.push_str("\r\n");

        Ok(result)
    }

    fn send_mail(&self) -> Result<()> {
        debug!("send_mail");

        let Some(ref account) = self.account else {
            bail!("no account");
        };

        let sender = account.owner.parse::<Address>()?;
        let recipients: Vec<_> = self.recipients
            .values()
            .map(|reverse_alias|
                reverse_alias
                    .as_ref()
                    .expect("no reverse_alias")
                    .address.parse::<Address>()
                    .expect("invalid address")
            )
            .collect();

        let envelope = Envelope::new(Some(sender), recipients)?;
        self.mailer.send_raw(&envelope, &self.data)
    }
}

impl Handler for HandlerImpl {
    fn helo(
        &mut self,
        ip: std::net::IpAddr,
        domain: &str,
    ) -> mailin_embedded::Response {
        debug!(?ip, domain, "helo");
        mailin_embedded::response::OK
    }

    fn auth_plain(
        &mut self,
        authorization_id: &str,
        authentication_id: &str,
        password: &str,
    ) -> mailin_embedded::Response {
        debug!(authorization_id, authentication_id, password, "auth_plain");

        self.account = self
            .settings
            .accounts
            .iter()
            .find(|x| x.user == authentication_id && x.password == password)
            .map(|x| x.to_owned());

        if self.account.is_none() {
            debug!("auth fail");
            return mailin_embedded::response::INVALID_CREDENTIALS;
        }

        debug!(?self.account, "auth ok");
        mailin_embedded::response::AUTH_OK
    }

    fn mail(
        &mut self,
        ip: std::net::IpAddr,
        domain: &str,
        from: &str,
    ) -> mailin_embedded::Response {
        debug!(?ip, domain, from, "mail");

        if self.account.is_none() {
            debug!("no account --> exit");
            return mailin_embedded::response::INTERNAL_ERROR;
        }

        mailin_embedded::response::OK
    }

    fn rcpt(&mut self, to: &str) -> mailin_embedded::Response {
        debug!(to, "rcpt");

        if self.account.is_none() {
            debug!("no account --> exit");
            return mailin_embedded::response::INTERNAL_ERROR;
        }

        self.recipient_email = Some(to.to_string());
        self.recipients.insert(to.to_string(), None);

        mailin_embedded::response::OK
    }

    fn data_start(
        &mut self,
        domain: &str,
        from: &str,
        is8bit: bool,
        to: &[String],
    ) -> mailin_embedded::Response {
        debug!(domain, from, is8bit, ?to, "data_start");

        for recipient in to.iter() {
            if !self.recipients.contains_key(recipient) {
                self.recipients.insert(recipient.clone(), None);
            }
        }

        mailin_embedded::response::OK
    }

    fn data(&mut self, buf: &[u8]) -> std::io::Result<()> {
        // debug!(len = buf.len(), "data");
        self.data.append(&mut buf.to_vec());
        Ok(())
    }

    fn data_end(&mut self) -> mailin_embedded::Response {
        debug!("data_end");

        match self.on_data_end() {
            Ok(_) => mailin_embedded::response::OK,
            Err(e) => {
                debug!(err = ?e, "error");
                mailin_embedded::response::INTERNAL_ERROR
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::FmtSubscriber;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::Ordering;
    use simplelogin_relay::settings;
    use super::*;

    fn setup() -> (HandlerImpl, Arc<MailerStub>) {
        let _ = tracing::subscriber::set_global_default(
            FmtSubscriber::builder()
                .with_max_level(tracing::Level::DEBUG)
                .finish()
        );

        let settings = Settings {
            name: "smtp-relay.example.com".to_string(),
            host: "1.2.3.4".to_string(),
            port: 1234,
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
            simplelogin: settings::SimpleLogin {
                address: "simplelogin-address".to_string(),
                apikey: "simplelogin-apikey".to_string(),
            },
            smtp: settings::Smtp {
                host: "smtp.example.com".to_string(),
                port: 1234,
                accept_invalid_certs: false,
                accept_invalid_hostnames: false,
            },
            accounts: vec![
                Account {
                    user: "user".to_string(),
                    password: "password".to_string(),
                    email: "user@public.com".to_string(),
                    owner: "user@private.com".to_string(),
                }
            ],
        };

        let mailer = Arc::new(MailerStub {
            mails: Arc::new(Mutex::new(vec![])),
        });

        let handler = HandlerImpl {
            settings: Arc::new(settings.clone()),
            api: Arc::new(ApiStub {
                aliases: Arc::new(Mutex::new(vec![
                    Alias { id: 1, email: "user@public.com".to_string() }
                ])),
                reverse_aliases_by_alias_id: Arc::new(Mutex::new(HashMap::new())),
                next_reverse_alias_id: AtomicU64::new(0),
            }),
            mailer: mailer.clone(),
            data: vec![],
            account: None,
            reverse_alias: None,
            recipient_email: None,
            recipients: HashMap::new(),
        };

        (handler, mailer)
    }

    struct ApiStub {
        aliases: Arc<Mutex<Vec<Alias>>>,
        reverse_aliases_by_alias_id: Arc<Mutex<HashMap<u64, Vec<ReverseAlias>>>>,
        next_reverse_alias_id: AtomicU64,
    }

    impl Api for ApiStub {
        fn find_alias_id(&self, account: &Account) -> Result<u64> {
            let aliases = self.aliases.lock().unwrap();

            for alias in aliases.iter() {
                if alias.email == account.email {
                    return Ok(alias.id);
                }
            }

            bail!("not found")
        }

        fn create_reverse_alias(
            &self,
            alias_id: u64,
            recipient_email: &str,
        ) -> Result<ReverseAlias> {
            let mut reverse_aliases_by_alias_id = self
                .reverse_aliases_by_alias_id
                .lock()
                .unwrap();

            let reverse_aliases = if let Some(x) = reverse_aliases_by_alias_id.get_mut(&alias_id) {
                x
            } else {
                let x = self.new_reverse_alias(recipient_email);
                reverse_aliases_by_alias_id.insert(alias_id, vec![x]);
                reverse_aliases_by_alias_id.get_mut(&alias_id).unwrap()
            };

            for ra in reverse_aliases.iter() {
                if ra.address == recipient_email {
                    return Ok(ra.clone());
                }
            }

            let ra = self.new_reverse_alias(recipient_email);
            reverse_aliases.push(ra.clone());

            Ok(ra)
        }
    }

    impl ApiStub {
        fn new_reverse_alias(&self, recipient_email: &str) -> ReverseAlias {
            let mut address = recipient_email
                .replace("@", "_at_")
                .replace(".", "_");

            address.push_str("@simplelogin.co");

            ReverseAlias {
                id: self.next_reverse_alias_id.fetch_add(1, Ordering::Relaxed),
                address: address.clone(),
                name_and_address: format!("Name <{}>", address),
            }
        }
    }

    struct MailerStub {
        mails: Arc<Mutex<Vec<Mail>>>
    }

    #[derive(Debug, PartialEq)]
    struct Mail {
        envelope: lettre::address::Envelope,
        email: String,
    }

    impl Mailer for MailerStub {
        fn send_raw(
            &self,
            envelope: &lettre::address::Envelope,
            email: &[u8],
        ) -> Result<()> {
            self.mails.lock().unwrap().push(Mail {
                envelope: envelope.clone(),
                email: String::from_utf8(email.to_vec()).unwrap(),
            });

            Ok(())
        }
    }

    #[test]
    fn verifies_credentials() {
        let (mut handler, _mailer) = setup();
        let client_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let client_domain = "dont.care.com";

        assert_eq!(
            mailin_embedded::response::OK,
            handler.helo(client_addr, client_domain)
        );

        assert_eq!(
            mailin_embedded::response::INVALID_CREDENTIALS,
            handler.auth_plain("dontcare", "bad-user", "password")
        );

        assert_eq!(
            mailin_embedded::response::INVALID_CREDENTIALS,
            handler.auth_plain("dontcare", "user", "bad-password")
        );

        assert_eq!(
            mailin_embedded::response::AUTH_OK,
            handler.auth_plain("dontcare", "user", "password")
        );
    }

    #[test]
    fn sends_mail() {
        let (mut handler, mailer) = setup();
        let client_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let client_domain = "dont.care.com";
        let _client_real_email = "user@private.com";
        let client_alias_email = "user@public.com";

        assert_eq!(
            mailin_embedded::response::OK,
            handler.helo(client_addr.clone(), client_domain)
        );

        assert_eq!(
            mailin_embedded::response::AUTH_OK,
            handler.auth_plain("dontcare", "user", "password")
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.mail(client_addr.clone(), client_domain, client_alias_email)
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.rcpt("recipient@example.com")
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.data_start(
                client_domain,
                client_alias_email,
                true,
                &["recipient@example.com".to_string()]
            )
        );

        let message = vec![
            "From: \"Sender\" <user@private.com>\r\n",
            "To: \"Recipient\" <recipient@example.com>\r\n",
            "Date: Tue, 15 Jan 2008 16:02:43 -0500\r\n",
            "Subject: Test message\r\n",
            "\r\n",
            "Hello\r\n",
            ".",
        ].join("");

        handler.data(message.as_bytes()).unwrap();

        assert_eq!(
            mailin_embedded::response::OK,
            handler.data_end()
        );

        let mails_actual = mailer.mails.lock().unwrap();
        insta::assert_debug_snapshot!(*mails_actual);
    }

    #[test]
    fn sends_mail_with_multiple_recipients() {
        let (mut handler, mailer) = setup();
        let client_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let client_domain = "dont.care.com";
        let _client_real_email = "user@private.com";
        let client_alias_email = "user@public.com";

        assert_eq!(
            mailin_embedded::response::OK,
            handler.helo(client_addr.clone(), client_domain)
        );

        assert_eq!(
            mailin_embedded::response::AUTH_OK,
            handler.auth_plain("dontcare", "user", "password")
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.mail(client_addr.clone(), client_domain, client_alias_email)
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.rcpt("first@example.com")
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.data_start(
                client_domain,
                client_alias_email,
                true,
                &[
                    "first@example.com".to_string(),
                    "second@example.com".to_string()
                ]
            )
        );

        let message = vec![
            "From: \"Sender\" <user@private.com>\r\n",
            "To: \"First\" <first@example.com>\r\n",
            "Cc: \"Second\" <second@example.com>\r\n",
            "Date: Tue, 15 Jan 2008 16:02:43 -0500\r\n",
            "Subject: Test message\r\n",
            "\r\n",
            "Hello\r\n",
            ".",
        ].join("");

        handler.data(message.as_bytes()).unwrap();

        assert_eq!(
            mailin_embedded::response::OK,
            handler.data_end()
        );

        let mails_actual = mailer.mails.lock().unwrap();
        insta::assert_debug_snapshot!(*mails_actual);
    }

    #[test]
    fn sends_mail_with_multiple_recipients_in_headers() {
        let (mut handler, mailer) = setup();
        let client_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let client_domain = "dont.care.com";
        let _client_real_email = "user@private.com";
        let client_alias_email = "user@public.com";

        assert_eq!(
            mailin_embedded::response::OK,
            handler.helo(client_addr.clone(), client_domain)
        );

        assert_eq!(
            mailin_embedded::response::AUTH_OK,
            handler.auth_plain("dontcare", "user", "password")
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.mail(client_addr.clone(), client_domain, client_alias_email)
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.rcpt("first@example.com")
        );

        assert_eq!(
            mailin_embedded::response::OK,
            handler.data_start(
                client_domain,
                client_alias_email,
                true,
                &[
                    "first@example.com".to_string(),
                    "second@example.com".to_string(),
                    "third@example.com".to_string(),
                ]
            )
        );

        let message = vec![
            "From: \"Sender\" <user@private.com>\r\n",
            "To: \"First\" <first@example.com>\r\n",
            "Cc: \"Second\" <second@example.com>, \"Third\" <third@example.com>\r\n",
            "Date: Tue, 15 Jan 2008 16:02:43 -0500\r\n",
            "Subject: Test message\r\n",
            "\r\n",
            "Hello\r\n",
            ".",
        ].join("");

        handler.data(message.as_bytes()).unwrap();

        assert_eq!(
            mailin_embedded::response::OK,
            handler.data_end()
        );

        let mails_actual = mailer.mails.lock().unwrap();
        insta::assert_debug_snapshot!(*mails_actual);
    }
}
