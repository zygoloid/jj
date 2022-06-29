// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::Path;

use chrono::DateTime;

use crate::backend::{Signature, Timestamp};

#[derive(Debug, Clone, Default)]
pub struct UserSettings {
    config: config::Config,
    timestamp: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct RepoSettings {
    _config: config::Config,
}

impl UserSettings {
    pub fn from_config(config: config::Config) -> Self {
        let timestamp = match config.get_string("user.timestamp") {
            Ok(timestamp_str) => match DateTime::parse_from_rfc3339(&timestamp_str) {
                Ok(datetime) => Some(Timestamp::from_datetime(datetime)),
                Err(_) => None,
            },
            Err(_) => None,
        };
        UserSettings { config, timestamp }
    }

    pub fn with_repo(&self, repo_path: &Path) -> Result<RepoSettings, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(self.config.clone())
            .add_source(
                config::File::from(repo_path.join("config"))
                    .required(false)
                    .format(config::FileFormat::Toml),
            )
            .build()?;
        Ok(RepoSettings { _config: config })
    }

    pub fn user_name(&self) -> String {
        self.config
            .get_string("user.name")
            .unwrap_or_else(|_| Self::user_name_placeholder().to_string())
    }

    pub fn user_name_placeholder() -> &'static str {
        "(no name configured)"
    }

    pub fn user_email(&self) -> String {
        self.config
            .get_string("user.email")
            .unwrap_or_else(|_| Self::user_email_placeholder().to_string())
    }

    pub fn user_email_placeholder() -> &'static str {
        "(no email configured)"
    }

    pub fn push_branch_prefix(&self) -> String {
        self.config
            .get_string("push.branch-prefix")
            .unwrap_or_else(|_| "push-".to_string())
    }

    pub fn signature(&self) -> Signature {
        let timestamp = self.timestamp.clone().unwrap_or_else(Timestamp::now);
        Signature {
            name: self.user_name(),
            email: self.user_email(),
            timestamp,
        }
    }

    pub fn open_commits(&self) -> bool {
        self.config.get_bool("ui.open-commits").unwrap_or(true)
    }

    pub fn config(&self) -> &config::Config {
        &self.config
    }
}
