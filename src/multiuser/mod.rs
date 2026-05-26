// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// src/multiuser/mod.rs — Multi-user access control for Runbound REST API.
//
// Model:
//   - Admin API key (existing master key) → full access, unrestricted.
//   - Admin user (admin: true) → same as master key, identified in audit logs.
//   - Regular user → restricted to DNS entries whose name ends with one of their
//     zone_prefixes; their own blacklist/feed entries (owner_user_id tag).
//
// Users are stored in $base_dir/users.json. The file is loaded at startup and
// reloaded on POST /reload. UserRegistry uses DashMap for O(1) key lookup on
// the hot auth path.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ── User account ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub id: String,
    pub username: String,
    /// 32-char hex API key (plain text — file must be 0600).
    pub api_key: String,
    /// DNS zone prefixes this user may manage, e.g. ["shop.example.com.", "api.example.com."].
    /// Empty list = no DNS access. Trailing dot is normalised on load.
    #[serde(default)]
    pub zone_prefixes: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Admin users have the same privileges as the master API key.
    #[serde(default)]
    pub admin: bool,
}

fn default_true() -> bool { true }

impl UserAccount {
    /// Check whether `name` (fully-qualified, trailing-dot normalised) is within
    /// one of this user's zone_prefixes.
    pub fn may_manage_name(&self, name: &str) -> bool {
        if self.admin { return true; }
        let n = if name.ends_with('.') { name } else { &format!("{}.", name) };
        self.zone_prefixes.iter().any(|prefix| {
            n == prefix.as_str() || n.ends_with(&format!(".{}", prefix))
        })
    }

    /// Generate a new random 32-char hex API key (128 bits, OS CSPRNG).
    pub fn generate_key() -> String {
        use std::fmt::Write as _;
        let raw = uuid::Uuid::new_v4();
        let mut s = String::with_capacity(32);
        for b in raw.as_bytes() {
            write!(s, "{:02x}", b).ok();
        }
        s
    }
}

// ── Serialised store ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UsersStore {
    #[serde(default)]
    pub users: Vec<UserAccount>,
}

// ── In-memory registry (DashMap for fast key lookup) ─────────────────────

pub struct UserRegistry {
    pub path: PathBuf,
    by_id:  DashMap<String, Arc<UserAccount>>,
    by_key: DashMap<String, Arc<UserAccount>>,
}

impl UserRegistry {
    pub fn load(path: &std::path::Path) -> Arc<Self> {
        let registry = Arc::new(Self {
            path: path.to_path_buf(),
            by_id:  DashMap::new(),
            by_key: DashMap::new(),
        });
        registry.reload_from_disk();
        registry
    }

    fn reload_from_disk(&self) {
        self.by_id.clear();
        self.by_key.clear();
        let Ok(data) = std::fs::read_to_string(&self.path) else { return };
        let Ok(store) = serde_json::from_str::<UsersStore>(&data) else {
            tracing::warn!(path = %self.path.display(), "users.json parse failed");
            return;
        };
        for mut u in store.users {
            // Normalise zone_prefix trailing dots.
            for p in &mut u.zone_prefixes {
                if !p.ends_with('.') { p.push('.'); }
            }
            let arc = Arc::new(u);
            self.by_id.insert(arc.id.clone(), Arc::clone(&arc));
            self.by_key.insert(arc.api_key.clone(), arc);
        }
        tracing::info!(count = self.by_id.len(), "Users loaded from disk");
    }

    pub fn reload(&self) {
        self.reload_from_disk();
    }

    pub fn by_api_key(&self, key: &str) -> Option<Arc<UserAccount>> {
        self.by_key.get(key).map(|v| Arc::clone(&v))
    }

    pub fn by_id(&self, id: &str) -> Option<Arc<UserAccount>> {
        self.by_id.get(id).map(|v| Arc::clone(&v))
    }

    pub fn all_users(&self) -> Vec<Arc<UserAccount>> {
        self.by_id.iter().map(|e| Arc::clone(e.value())).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    fn save_store(&self, store: &UsersStore) -> Result<(), String> {
        let data = serde_json::to_vec_pretty(store)
            .map_err(|e| format!("serialize users: {e}"))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &data)
            .map_err(|e| format!("write users tmp: {e}"))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("rename users store: {e}"))?;
        Ok(())
    }

    fn current_store(&self) -> UsersStore {
        let users = self.by_id.iter()
.map(|e| e.value().as_ref().clone())
            .collect();
        UsersStore { users }
    }

    pub fn create_user(
        &self,
        username: String,
        zone_prefixes: Vec<String>,
        admin: bool,
    ) -> Result<Arc<UserAccount>, String> {
        // Reject duplicate usernames.
        if self.by_id.iter().any(|e| e.value().username == username) {
            return Err(format!("Username '{}' already exists", username));
        }
        let prefixes: Vec<String> = zone_prefixes.into_iter().map(|mut p| {
            if !p.ends_with('.') { p.push('.'); }
            p
        }).collect();
        let u = UserAccount {
            id: uuid::Uuid::new_v4().to_string(),
            username,
            api_key: UserAccount::generate_key(),
            zone_prefixes: prefixes,
            enabled: true,
            admin,
        };
        let arc = Arc::new(u);
        self.by_id.insert(arc.id.clone(), Arc::clone(&arc));
        self.by_key.insert(arc.api_key.clone(), Arc::clone(&arc));
        let mut store = self.current_store();
        store.users.push((*arc).clone());
        self.save_store(&store)?;
        Ok(arc)
    }

    pub fn delete_user(&self, id: &str) -> bool {
        let Some(entry) = self.by_id.remove(id) else { return false };
        self.by_key.remove(&entry.1.api_key);
        let mut store = self.current_store();
        store.users.retain(|u| u.id != id);
        let _ = self.save_store(&store);
        true
    }

    pub fn rotate_key(&self, id: &str) -> Option<String> {
        let arc = self.by_id.get(id)?.clone();
        let old_key = arc.api_key.clone();
        let new_key = UserAccount::generate_key();
        let updated = Arc::new(UserAccount {
            id: arc.id.clone(),
            username: arc.username.clone(),
            api_key: new_key.clone(),
            zone_prefixes: arc.zone_prefixes.clone(),
            enabled: arc.enabled,
            admin: arc.admin,
        });
        self.by_key.remove(&old_key);
        self.by_key.insert(new_key.clone(), Arc::clone(&updated));
        self.by_id.insert(arc.id.clone(), updated);
        let mut store = self.current_store();
        for u in &mut store.users {
            if u.id == *arc.id { u.api_key = new_key.clone(); }
        }
        let _ = self.save_store(&store);
        Some(new_key)
    }
}

// ── Request context injected by auth middleware ───────────────────────────

#[derive(Clone, Debug)]
pub struct RequestUser {
    pub id: String,
    pub username: String,
    pub admin: bool,
    pub zone_prefixes: Vec<String>,
}

impl RequestUser {
    /// Synthesised admin context when the master API key is used (no user object).
    pub fn admin_context() -> Self {
        Self {
            id: "admin".to_string(),
            username: "admin".to_string(),
            admin: true,
            zone_prefixes: vec![],
        }
    }

    pub fn from_account(u: &UserAccount) -> Self {
        Self {
            id: u.id.clone(),
            username: u.username.clone(),
            admin: u.admin,
            zone_prefixes: u.zone_prefixes.clone(),
        }
    }

    pub fn may_manage_name(&self, name: &str) -> bool {
        if self.admin { return true; }
        let n = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{}.", name)
        };
        self.zone_prefixes.iter().any(|prefix| {
            n == *prefix || n.ends_with(&format!(".{}", prefix))
        })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn may_manage_name_prefix_match() {
        let u = UserAccount {
            id: "1".into(), username: "alice".into(), api_key: "k".into(),
            zone_prefixes: vec!["shop.example.com.".into()],
            enabled: true, admin: false,
        };
        assert!(u.may_manage_name("shop.example.com."));
        assert!(u.may_manage_name("www.shop.example.com."));
        assert!(!u.may_manage_name("example.com."));
        assert!(!u.may_manage_name("other.example.com."));
    }

    #[test]
    fn may_manage_name_admin_always_true() {
        let u = UserAccount {
            id: "1".into(), username: "admin".into(), api_key: "k".into(),
            zone_prefixes: vec![],
            enabled: true, admin: true,
        };
        assert!(u.may_manage_name("anything.example.com."));
    }

    #[test]
    fn request_user_may_manage_name_no_trailing_dot() {
        let ru = RequestUser {
            id: "1".into(), username: "bob".into(), admin: false,
            zone_prefixes: vec!["api.example.com.".into()],
        };
        // name without trailing dot should still match
        assert!(ru.may_manage_name("api.example.com"));
        assert!(ru.may_manage_name("v2.api.example.com"));
        assert!(!ru.may_manage_name("other.example.com"));
    }

    #[test]
    fn generate_key_is_32_chars_hex() {
        let k = UserAccount::generate_key();
        assert_eq!(k.len(), 32);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn registry_crud_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.json");
        let reg = UserRegistry::load(&path);
        assert!(reg.is_empty());

        let u = reg.create_user("alice".into(), vec!["alice.test.".into()], false).unwrap();
        assert_eq!(u.username, "alice");
        assert_eq!(reg.by_api_key(&u.api_key).unwrap().username, "alice");

        // Duplicate username rejected
        assert!(reg.create_user("alice".into(), vec![], false).is_err());

        // File was written
        assert!(path.exists());

        // Reload from disk
        let reg2 = UserRegistry::load(&path);
        assert_eq!(reg2.all_users().len(), 1);
        assert!(reg2.by_id(&u.id).is_some());

        // Delete
        assert!(reg.delete_user(&u.id));
        assert!(reg.is_empty());
    }
}
