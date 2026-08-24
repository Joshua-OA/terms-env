//! Domain models: env files, variables, project namespaces.

use serde::{Deserialize, Serialize};

/// A single environment variable. Keys are unique within an [`EnvFile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

/// An ordered collection of env variables. Order is insertion order;
/// setting an existing key updates in place.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvFile {
    vars: Vec<EnvVar>,
}

impl EnvFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.vars.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &EnvVar> {
        self.vars.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.vars.iter().map(|v| v.key.as_str())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.position(key).map(|i| self.vars[i].value.as_str())
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.position(key).is_some()
    }

    /// Insert or update in place. Updating preserves the original position.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let (key, value) = (key.into(), value.into());
        match self.position(&key) {
            Some(i) => self.vars[i].value = value,
            None => self.vars.push(EnvVar { key, value }),
        }
    }

    pub fn remove(&mut self, key: &str) -> bool {
        match self.position(key) {
            Some(i) => {
                self.vars.remove(i);
                true
            }
            None => false,
        }
    }

    fn position(&self, key: &str) -> Option<usize> {
        self.vars.iter().position(|v| v.key == key)
    }
}
