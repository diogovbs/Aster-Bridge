//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use crate::api_client::{ApiClient, ContactRecord, CreateContactRequest, UpdateContactRequest};
use crate::auth::session::Session;
use crate::crypto::contacts::{ContactsKeys, CONTACT_DATA_VERSION};
use crate::error::{BridgeError, Result};

const PAGE_SIZE: u32 = 200;
const MAX_PAGES: usize = 200;
const CACHE_TTL: Duration = Duration::from_secs(5);
const DAV_UID_FIELD: &str = "dav_uid";
const MAX_VCARD_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct ContactEntry {
    pub uid: String,
    pub contact_id: String,
    pub etag: String,
    pub vcard: String,
}

struct CachedListing {
    entries: Arc<Vec<ContactEntry>>,
    index: HashMap<String, usize>,
    fetched_at: Instant,
}

impl CachedListing {
    fn new(entries: Vec<ContactEntry>, fetched_at: Instant) -> Self {
        let index = entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.uid.clone(), i))
            .collect();
        Self {
            entries: Arc::new(entries),
            index,
            fetched_at,
        }
    }

    fn find(&self, uid: &str) -> Option<&ContactEntry> {
        self.index.get(uid).map(|&i| &self.entries[i])
    }

    fn upsert(&mut self, entry: ContactEntry) {
        let entries = Arc::make_mut(&mut self.entries);
        match self.index.get(&entry.uid) {
            Some(&i) => entries[i] = entry,
            None => {
                self.index.insert(entry.uid.clone(), entries.len());
                entries.push(entry);
            }
        }
    }

    fn remove(&mut self, uid: &str) {
        let Some(i) = self.index.remove(uid) else {
            return;
        };
        let entries = Arc::make_mut(&mut self.entries);
        entries.swap_remove(i);
        if let Some(moved) = entries.get(i) {
            self.index.insert(moved.uid.clone(), i);
        }
    }
}

pub struct ContactsStore {
    client: Arc<ApiClient>,
    session: Arc<RwLock<Session>>,
    cache: RwLock<Option<CachedListing>>,
    // Held while the listing is fetched from the server, so concurrent
    // readers that find the cache stale wait for one fetch instead of each
    // starting their own. Writers hold it for the whole write so a refresh
    // that started before the write can't overwrite the updated cache.
    refresh_lock: Mutex<()>,
    write_lock: Mutex<()>,
}

pub fn entry_etag(vcard: &str) -> String {
    let digest = Sha256::digest(vcard.as_bytes());
    format!("\"{}\"", hex_prefix(&digest, 16))
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes
        .iter()
        .take(len)
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub fn collection_ctag(entries: &[ContactEntry]) -> String {
    let mut hasher = Sha256::new();
    let mut sorted: Vec<&ContactEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.uid.cmp(&b.uid));
    for entry in sorted {
        hasher.update(entry.uid.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.etag.as_bytes());
        hasher.update(b"\0");
    }
    format!("\"{}\"", hex_prefix(&hasher.finalize(), 16))
}

impl ContactsStore {
    pub fn new(client: Arc<ApiClient>, session: Arc<RwLock<Session>>) -> Self {
        Self {
            client,
            session,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            write_lock: Mutex::new(()),
        }
    }

    async fn keys(&self) -> Result<ContactsKeys> {
        let session = self.session.read().await;
        let Some(data_kek) = session.data_kek.as_ref() else {
            return Err(BridgeError::Crypto(
                "contacts key unavailable - sign in again".to_string(),
            ));
        };
        ContactsKeys::from_data_kek_b64(data_kek)
    }

    async fn access_token(&self) -> String {
        self.session.read().await.access_token.to_string()
    }

    async fn fetch_entries(&self) -> Result<Vec<ContactEntry>> {
        let keys = self.keys().await?;
        let token = self.access_token().await;

        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;
        let mut skipped_integrity = 0usize;
        let mut skipped_decrypt = 0usize;

        for _ in 0..MAX_PAGES {
            let page = self
                .client
                .list_contacts(&token, PAGE_SIZE, cursor.as_deref())
                .await?;

            for record in &page.items {
                match record_to_entry(&keys, record) {
                    Ok(entry) => entries.push(entry),
                    Err(RecordSkip::Integrity) => skipped_integrity += 1,
                    Err(RecordSkip::Decrypt) => skipped_decrypt += 1,
                }
            }

            match page.next_cursor {
                Some(next) if page.has_more => cursor = Some(next),
                _ => break,
            }
        }

        if skipped_integrity > 0 || skipped_decrypt > 0 {
            tracing::warn!(
                "skipped {} contacts this sync, {} failed an integrity check and {} could not be decrypted",
                skipped_integrity + skipped_decrypt,
                skipped_integrity,
                skipped_decrypt
            );
        }

        let mut seen = HashMap::new();
        entries.retain(|entry| seen.insert(entry.uid.clone(), ()).is_none());

        Ok(entries)
    }

    pub async fn invalidate(&self) {
        *self.cache.write().await = None;
    }

    async fn fresh_cached<R>(&self, f: impl FnOnce(&CachedListing) -> R) -> Option<R> {
        let cache = self.cache.read().await;
        cache
            .as_ref()
            .filter(|cached| cached.fetched_at.elapsed() < CACHE_TTL)
            .map(f)
    }

    // Fetches the whole address book and stores it as the cache. The caller
    // must hold refresh_lock.
    async fn refresh_locked(&self) -> Result<()> {
        let fetched_at = Instant::now();
        let entries = self.fetch_entries().await?;
        *self.cache.write().await = Some(CachedListing::new(entries, fetched_at));
        Ok(())
    }

    async fn with_listing<R>(&self, f: impl Fn(&CachedListing) -> R) -> Result<R> {
        if let Some(out) = self.fresh_cached(&f).await {
            return Ok(out);
        }
        let _refresh = self.refresh_lock.lock().await;
        if let Some(out) = self.fresh_cached(&f).await {
            return Ok(out);
        }
        self.refresh_locked().await?;
        let cache = self.cache.read().await;
        let cached = cache
            .as_ref()
            .ok_or_else(|| BridgeError::Api("contacts listing unavailable".to_string()))?;
        Ok(f(cached))
    }

    pub async fn list(&self) -> Result<Arc<Vec<ContactEntry>>> {
        self.with_listing(|cached| cached.entries.clone()).await
    }

    pub async fn get(&self, uid: &str) -> Result<Option<ContactEntry>> {
        self.with_listing(|cached| cached.find(uid).cloned()).await
    }

    // Refreshes the listing from the server and returns the current entry for
    // uid. Writers call this with refresh_lock held so the write is decided
    // against current server state.
    async fn current_entry_locked(&self, uid: &str) -> Result<Option<ContactEntry>> {
        self.refresh_locked().await?;
        Ok(self
            .cache
            .read()
            .await
            .as_ref()
            .and_then(|cached| cached.find(uid).cloned()))
    }

    // Builds the entry for a contact that was just written from the server's
    // copy of that one record, the same way a full listing would, and puts it
    // into the cache in place.
    async fn store_written_entry(
        &self,
        token: &str,
        keys: &ContactsKeys,
        contact_id: &str,
    ) -> Result<ContactEntry> {
        let record = self.client.get_contact(token, contact_id).await?;
        let entry = record_to_entry(keys, &record)
            .map_err(|_| BridgeError::Api("contact was not stored".to_string()))?;
        if let Some(cached) = self.cache.write().await.as_mut() {
            cached.upsert(entry.clone());
        }
        Ok(entry)
    }

    pub async fn put(&self, uid: &str, vcard: &str) -> Result<(ContactEntry, bool)> {
        if vcard.len() > MAX_VCARD_BYTES {
            return Err(BridgeError::Api("vcard too large".to_string()));
        }
        if !is_safe_uid(uid) {
            return Err(BridgeError::Api("unsupported contact name".to_string()));
        }

        let _guard = self.write_lock.lock().await;
        let _refresh = self.refresh_lock.lock().await;

        if let Some(body_uid) = super::vcard::extract_uid(vcard) {
            if body_uid != uid {
                tracing::debug!("carddav put uid mismatch: href {} body {}", uid, body_uid);
            }
        }

        let mut payload = super::vcard::vcard_to_contact(vcard);
        payload.insert(DAV_UID_FIELD.to_string(), Value::from(uid));

        let keys = self.keys().await?;
        let token = self.access_token().await;
        let existing = self.current_entry_locked(uid).await?;

        let sealed = keys.encrypt_data(&Value::Object(payload.clone()))?;
        let tokens = search_tokens(&keys, &payload);

        let (contact_id, created) = match &existing {
            Some(entry) => {
                self.client
                    .update_contact(
                        &token,
                        &entry.contact_id,
                        &UpdateContactRequest {
                            encrypted_data: sealed.encrypted_data,
                            data_nonce: sealed.data_nonce,
                            integrity_hash: sealed.integrity_hash,
                            name_search_token: tokens.name,
                            email_search_token: tokens.email,
                            company_search_token: tokens.company,
                        },
                    )
                    .await?;
                (entry.contact_id.clone(), false)
            }
            None => {
                let response = self
                    .client
                    .create_contact(
                        &token,
                        &CreateContactRequest {
                            contact_token: tokens.contact,
                            name_search_token: tokens.name,
                            email_search_token: tokens.email,
                            company_search_token: tokens.company,
                            encrypted_data: sealed.encrypted_data,
                            data_nonce: sealed.data_nonce,
                            integrity_hash: sealed.integrity_hash,
                            data_version: CONTACT_DATA_VERSION,
                        },
                    )
                    .await?;
                (response.id, true)
            }
        };

        let entry = match self.store_written_entry(&token, &keys, &contact_id).await {
            Ok(entry) if entry.uid == uid => entry,
            _ => {
                self.refresh_locked().await?;
                self.cache
                    .read()
                    .await
                    .as_ref()
                    .and_then(|cached| cached.find(uid).cloned())
                    .ok_or_else(|| BridgeError::Api("contact was not stored".to_string()))?
            }
        };

        Ok((entry, created))
    }

    pub async fn delete(&self, uid: &str) -> Result<bool> {
        let _guard = self.write_lock.lock().await;
        let _refresh = self.refresh_lock.lock().await;

        let Some(entry) = self.current_entry_locked(uid).await? else {
            return Ok(false);
        };

        let token = self.access_token().await;
        self.client.delete_contact(&token, &entry.contact_id).await?;
        if let Some(cached) = self.cache.write().await.as_mut() {
            cached.remove(uid);
        }

        Ok(true)
    }
}

enum RecordSkip {
    Integrity,
    Decrypt,
}

fn record_to_entry(
    keys: &ContactsKeys,
    record: &ContactRecord,
) -> std::result::Result<ContactEntry, RecordSkip> {
    if let (Some(hash), Some(version)) = (record.integrity_hash.as_deref(), record.data_version) {
        if !keys.verify_integrity_hash(&record.encrypted_data, &record.data_nonce, version, hash) {
            tracing::debug!(
                "contact {} failed its integrity check and was skipped",
                record.id
            );
            return Err(RecordSkip::Integrity);
        }
    }

    let payload = match keys.decrypt_data(&record.encrypted_data, &record.data_nonce) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::debug!("contact {} could not be decrypted: {}", record.id, e);
            return Err(RecordSkip::Decrypt);
        }
    };

    let uid = payload
        .get(DAV_UID_FIELD)
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty() && is_safe_uid(v))
        .unwrap_or(record.id.as_str())
        .to_string();

    let vcard = super::vcard::contact_to_vcard(&uid, &payload, &record.updated_at);
    Ok(ContactEntry {
        uid,
        contact_id: record.id.clone(),
        etag: entry_etag(&vcard),
        vcard,
    })
}

struct SearchTokens {
    contact: String,
    name: Option<String>,
    email: Option<String>,
    company: Option<String>,
}

fn search_tokens(keys: &ContactsKeys, payload: &Map<String, Value>) -> SearchTokens {
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    let first_name = text("first_name");
    let last_name = text("last_name");
    let company = text("company");
    let emails: Vec<String> = payload
        .get("emails")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .map(|v| v.to_string())
                .collect()
        })
        .unwrap_or_default();

    let full_name = format!("{} {}", first_name, last_name).trim().to_string();

    SearchTokens {
        contact: keys.contact_token(&first_name, &last_name, &emails),
        name: (!full_name.is_empty()).then(|| keys.search_token(&full_name)),
        email: emails
            .first()
            .filter(|v| !v.is_empty())
            .map(|v| keys.search_token(v)),
        company: (!company.is_empty()).then(|| keys.search_token(&company)),
    }
}

pub fn is_safe_uid(uid: &str) -> bool {
    !uid.is_empty()
        && uid.len() <= 255
        && uid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+' | '~'))
        && !uid.starts_with('.')
        && uid != ".."
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn entry(uid: &str, vcard: &str) -> ContactEntry {
        ContactEntry {
            uid: uid.to_string(),
            contact_id: uid.to_string(),
            etag: entry_etag(vcard),
            vcard: vcard.to_string(),
        }
    }

    #[test]
    fn etags_are_quoted_and_content_bound() {
        let a = entry_etag("BEGIN:VCARD\r\nEND:VCARD\r\n");
        let b = entry_etag("BEGIN:VCARD\r\nFN:A\r\nEND:VCARD\r\n");

        assert!(a.starts_with('"') && a.ends_with('"'));
        assert_eq!(a.len(), 34);
        assert_ne!(a, b);
    }

    #[test]
    fn ctag_is_order_independent_but_content_sensitive() {
        let first = entry("a", "one");
        let second = entry("b", "two");

        assert_eq!(
            collection_ctag(&[first.clone(), second.clone()]),
            collection_ctag(&[second.clone(), first.clone()])
        );
        assert_ne!(
            collection_ctag(std::slice::from_ref(&first)),
            collection_ctag(&[first, second])
        );
    }

    #[test]
    fn rejects_path_traversal_and_control_characters_in_uids() {
        assert!(is_safe_uid("3f8a-1234"));
        assert!(is_safe_uid("ada@example.com"));
        assert!(!is_safe_uid(".."));
        assert!(!is_safe_uid("../../etc/passwd"));
        assert!(!is_safe_uid("a/b"));
        assert!(!is_safe_uid("a\\b"));
        assert!(!is_safe_uid(""));
        assert!(!is_safe_uid(".hidden"));
        assert!(!is_safe_uid(&"x".repeat(256)));
    }

    #[test]
    fn search_tokens_cover_name_email_and_company() {
        let keys = ContactsKeys::from_data_kek_b64(
            &base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
        )
        .unwrap();
        let payload = serde_json::json!({
            "first_name": "Ada",
            "last_name": "Lovelace",
            "company": "Engines",
            "emails": ["ada@example.com"],
        });
        let tokens = search_tokens(&keys, payload.as_object().unwrap());

        assert_eq!(tokens.name.unwrap(), keys.search_token("Ada Lovelace"));
        assert_eq!(tokens.email.unwrap(), keys.search_token("ada@example.com"));
        assert_eq!(tokens.company.unwrap(), keys.search_token("Engines"));
        assert_eq!(
            tokens.contact,
            keys.contact_token("Ada", "Lovelace", &["ada@example.com".to_string()])
        );
    }

    #[test]
    fn search_tokens_are_absent_for_empty_fields() {
        let keys = ContactsKeys::from_data_kek_b64(
            &base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
        )
        .unwrap();
        let payload = serde_json::json!({
            "first_name": "",
            "last_name": "",
            "emails": [],
        });
        let tokens = search_tokens(&keys, payload.as_object().unwrap());

        assert!(tokens.name.is_none());
        assert!(tokens.email.is_none());
        assert!(tokens.company.is_none());
    }
}
