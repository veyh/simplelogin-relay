#[derive(serde::Deserialize, Debug, Clone)]
pub struct Settings {
    pub name: String,
    pub host: String,
    pub port: u16,

    pub cert_path: String,
    pub key_path: String,

    pub simplelogin: SimpleLogin,
    pub smtp: Smtp,
    pub accounts: Vec<Account>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct SimpleLogin {
    pub address: String,
    pub apikey: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct Smtp {
    pub host: String,
    pub port: u16,
    pub accept_invalid_hostnames: bool,
    pub accept_invalid_certs: bool,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct Account {
    pub user: String,
    pub password: String,
    pub email: String,
    pub owner: String,
}
