use anyhow::{bail, Result};
use config::Config;
use mailin_embedded::{AuthMechanism, Handler, Server, SslConfig};
use once_cell::sync::OnceCell;
use simplelogin_relay::settings;
use tracing::debug;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static SETTINGS: OnceCell<settings::Settings> = OnceCell::new();

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simplelogin_relay=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let settings = parse_settings().unwrap();
    SETTINGS.set(settings.clone()).unwrap();

    let handler = HandlerImpl::new();
    let mut server = Server::new(handler);

    server
        .with_name(settings.name)
        .with_ssl(SslConfig::SelfSigned {
            cert_path: settings.cert_path,
            key_path: settings.key_path,
        })
        .unwrap()
        .with_addr(format!("{}:{}", settings.host, settings.port))
        .unwrap()
        .with_auth(AuthMechanism::Plain)
        .with_num_threads(1);

    server.serve().unwrap();
    Ok(())
}

fn parse_settings() -> Result<settings::Settings> {
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
    data: Vec<u8>,
}

impl HandlerImpl {
    fn new() -> Self {
        Self { data: vec![] }
    }

    fn on_data_end(&mut self) -> Result<()> {
        let data_str = String::from_utf8_lossy(&self.data);
        debug!("data_str: {:?}", data_str);
        println!("{}", data_str);

        Ok(())
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

        mailin_embedded::response::AUTH_OK
    }

    fn mail(
        &mut self,
        ip: std::net::IpAddr,
        domain: &str,
        from: &str,
    ) -> mailin_embedded::Response {
        debug!(?ip, domain, from, "mail");
        mailin_embedded::response::OK
    }

    fn rcpt(&mut self, to: &str) -> mailin_embedded::Response {
        debug!(to, "rcpt");
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
        mailin_embedded::response::OK
    }

    fn data(&mut self, buf: &[u8]) -> std::io::Result<()> {
        debug!(len = buf.len(), "data");
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
