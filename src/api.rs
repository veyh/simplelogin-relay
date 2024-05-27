use anyhow::{bail, Result};
use serde_json::json;
use std::sync::Arc;
use tracing::debug;
use ureq::Agent;

use crate::settings::{Account, Settings};
use crate::types::*;

#[derive(serde::Deserialize, Debug, Clone)]
pub struct AliasesResponse {
    pub aliases: Vec<Alias>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct Alias {
    pub email: String,
    pub id: u64,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct CreateReverseAliasResponse {
    reverse_alias: String,
    reverse_alias_address: String,
}

pub trait Api: Send + Sync {
    fn find_alias_id(&self, account: &Account) -> Result<u64>;
    fn create_reverse_alias(
        &self,
        alias_id: u64,
        recipient_email: &str,
    ) -> Result<ReverseAlias>;
}

#[derive(Clone)]
pub struct ApiImpl {
    pub agent: Agent,
    pub settings: Arc<Settings>,
}

impl Api for ApiImpl {
    fn find_alias_id(&self, account: &Account) -> Result<u64> {
        debug!("find_alias_id");

        let req_body = json!({
          "query": account.email,
        });

        let response = self
            .agent
            .get(&format!(
                "{}/api/v2/aliases",
                self.settings.simplelogin.address
            ))
            .set("Authentication", &self.settings.simplelogin.apikey)
            .set("Content-Type", "application/json")
            .query("page_id", "0")
            .send_string(&req_body.to_string())?
            .into_reader();

        let res_body: AliasesResponse = serde_json::from_reader(response)?;
        let Some(alias) =
            res_body.aliases.iter().find(|x| x.email == account.email)
        else {
            bail!("no alias exists for this email");
        };

        Ok(alias.id)
    }

    fn create_reverse_alias(
        &self,
        alias_id: u64,
        recipient_email: &str,
    ) -> Result<ReverseAlias> {
        debug!(alias_id, "create_reverse_alias");

        if self.is_reverse_alias(recipient_email) {
            return Ok(ReverseAlias {
                id: alias_id,
                address: recipient_email.to_string(),
                name_and_address: recipient_email.to_string(),
            });
        }

        let req_body = json!({ "contact": recipient_email });
        let response = self
            .agent
            .post(&format!(
                "{}/api/aliases/{}/contacts",
                self.settings.simplelogin.address, alias_id
            ))
            .set("Authentication", &self.settings.simplelogin.apikey)
            .set("Content-Type", "application/json")
            .send_string(&req_body.to_string())?
            .into_reader();

        let res_body: CreateReverseAliasResponse =
            serde_json::from_reader(response)?;

        Ok(ReverseAlias {
            id: alias_id,
            address: res_body.reverse_alias_address,
            name_and_address: res_body.reverse_alias,
        })
    }
}

impl ApiImpl {
    fn is_reverse_alias(&self, email: &str) -> bool {
        // Eg. "user_at_example_com_hd784hgh@simplelogin.co"
        email.ends_with("@simplelogin.co")
    }
}
