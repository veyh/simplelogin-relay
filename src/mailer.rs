use anyhow::Result;
use lettre::transport::smtp::client::Tls;
use lettre::transport::smtp::client::TlsParametersBuilder;
use lettre::SmtpTransport;
use lettre::Transport;

use crate::settings::Settings;

pub trait Mailer: Send + Sync {
    fn send_raw(
        &self,
        envelope: &lettre::address::Envelope,
        email: &[u8],
    ) -> Result<()>;
}

#[derive(Clone)]
pub struct MailerImpl {
    pub mailer: SmtpTransport,
}

impl Mailer for MailerImpl {
    fn send_raw(
        &self,
        envelope: &lettre::address::Envelope,
        data: &[u8],
    ) -> Result<()> {
        self.mailer.send_raw(envelope, data)?;
        Ok(())
    }
}

impl MailerImpl {
    pub fn new(settings: &Settings) -> Result<Self> {
        let tls_parameters = {
            let mut b = TlsParametersBuilder::new(settings.smtp.host.clone());

            if settings.smtp.accept_invalid_hostnames {
                b = b.dangerous_accept_invalid_hostnames(true);
            }

            if settings.smtp.accept_invalid_certs {
                b = b.dangerous_accept_invalid_certs(true);
            }

            b.build()?
        };

        let mailer =
            SmtpTransport::builder_dangerous(settings.smtp.host.clone())
                .port(settings.smtp.port)
                .tls(Tls::Wrapper(tls_parameters))
                .build();

        Ok(Self { mailer })
    }
}
