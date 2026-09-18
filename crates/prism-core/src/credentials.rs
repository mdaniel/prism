//! Server launch values live in the OS credential store, never in saved JSON.
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{PrismConfig, ServerConfig};
use crate::error::{Error, Result};

const SERVICE: &str = "dev.prism.gateway.servers";
// Windows generic credentials have a 2560-byte limit. Chunking also handles long env values.
const CHUNK_BYTES: usize = 2000;
const MAX_BYTES: usize = 1024 * 1024;

pub(crate) trait CredentialStore: Send + Sync {
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    fn delete(&self, key: &str) -> Result<()>;
}

#[derive(Default)]
pub(crate) struct NativeStore(Mutex<()>);

fn unavailable() -> Error {
    Error::Gateway("credential storage is locked, unavailable, or missing an entry. Unlock your credential store or re-save server settings.".into())
}

impl CredentialStore for NativeStore {
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let _guard = self.0.lock().map_err(|_| unavailable())?;
        keyring::Entry::new(SERVICE, key)
            .and_then(|entry| entry.set_secret(value))
            .map_err(|_| unavailable())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let _guard = self.0.lock().map_err(|_| unavailable())?;
        keyring::Entry::new(SERVICE, key)
            .and_then(|entry| entry.get_secret())
            .map_err(|_| unavailable())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let _guard = self.0.lock().map_err(|_| unavailable())?;
        match keyring::Entry::new(SERVICE, key).and_then(|entry| entry.delete_credential()) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(unavailable()),
        }
    }
}

/// A static file-backed credential store (`credentials.json`) that avoids OS keychain prompts.
pub(crate) struct FileStore {
    path: PathBuf,
    entries: RwLock<HashMap<String, Vec<u8>>>,
}

impl FileStore {
    pub(crate) fn new(path: PathBuf) -> Result<Self> {
        let mut entries = HashMap::new();
        if path.exists() {
            let data = std::fs::read(&path)
                .map_err(|e| Error::Gateway(format!("could not read credentials file: {e}")))?;
            if !data.is_empty() {
                let raw_map: BTreeMap<String, String> = serde_json::from_slice(&data)
                    .map_err(|e| Error::Gateway(format!("invalid credentials file JSON: {e}")))?;
                use base64::engine::general_purpose::STANDARD as BASE64;
                use base64::Engine;
                for (k, v) in raw_map {
                    let bytes = match BASE64.decode(&v) {
                        Ok(b) => b,
                        Err(_) => v.into_bytes(),
                    };
                    entries.insert(k, bytes);
                }
            }
        }
        Ok(Self {
            path,
            entries: RwLock::new(entries),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self) -> Result<()> {
        let entries = self.entries.read().map_err(|_| unavailable())?;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        let mut raw_map = BTreeMap::new();
        for (k, v) in entries.iter() {
            raw_map.insert(k.clone(), BASE64.encode(v));
        }
        let json = serde_json::to_string_pretty(&raw_map)
            .map_err(|e| Error::Gateway(format!("could not serialize credentials: {e}")))?;
        crate::storage::atomic_write(&self.path, json.as_bytes())
            .map_err(|e| Error::Gateway(format!("could not save credentials: {e}")))?;
        Ok(())
    }
}

impl CredentialStore for FileStore {
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        {
            let mut entries = self.entries.write().map_err(|_| unavailable())?;
            entries.insert(key.to_string(), value.to_vec());
        }
        self.persist()
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let entries = self.entries.read().map_err(|_| unavailable())?;
        entries.get(key).cloned().ok_or_else(unavailable)
    }

    fn delete(&self, key: &str) -> Result<()> {
        let removed = {
            let mut entries = self.entries.write().map_err(|_| unavailable())?;
            entries.remove(key).is_some()
        };
        if removed {
            self.persist()?;
        }
        Ok(())
    }
}

/// Create the default credential store. Defaults to `FileStore` (`credentials.json`),
/// unless `PRISM_CREDENTIAL_STORE` is explicitly set to `native` or `keychain`.
pub(crate) fn default_store(config_path: &Path) -> Result<Arc<dyn CredentialStore>> {
    let provider = std::env::var("PRISM_CREDENTIAL_STORE").unwrap_or_else(|_| "file".into());
    match provider.to_lowercase().as_str() {
        "native" | "keychain" | "os" => Ok(Arc::new(NativeStore::default())),
        _ => {
            let cred_path = std::env::var("PRISM_CREDENTIALS_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| config_path.with_file_name("credentials.json"));
            Ok(Arc::new(FileStore::new(cred_path)?))
        }
    }
}

// Deliberately no Debug: launch settings may contain credentials.
#[derive(Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct LaunchSettings {
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    /// Request headers of a remote server. Absent in records written before remote servers existed.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

fn has_plaintext(config: &ServerConfig) -> bool {
    !config.args.is_empty() || !config.env.is_empty() || !config.headers.is_empty()
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    chunks: usize,
    digest: Vec<u8>,
}

fn manifest(store: &dyn CredentialStore, id: &str) -> Result<Manifest> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| Error::Invalid("invalid server credential reference".into()))?;
    let manifest: Manifest = serde_json::from_slice(&store.get(id)?).map_err(|_| unavailable())?;
    if manifest.chunks == 0 || manifest.chunks > MAX_BYTES.div_ceil(CHUNK_BYTES) {
        return Err(unavailable());
    }
    Ok(manifest)
}

/// Read a chunked, digest-checked record written by [`put_blob`].
pub(crate) fn get_blob(store: &dyn CredentialStore, id: &str) -> Result<Vec<u8>> {
    let manifest = manifest(store, id)?;
    let mut bytes = Vec::new();
    for chunk in 0..manifest.chunks {
        let value = store.get(&format!("{id}/{chunk}"))?;
        if value.len() > CHUNK_BYTES {
            return Err(unavailable());
        }
        bytes.extend(value);
    }
    if Sha256::digest(&bytes).as_slice() != manifest.digest {
        return Err(unavailable());
    }
    Ok(bytes)
}

/// Write a record under `id` (a UUID) in chunks with a manifest, verifying it reads back.
/// A partial write is rolled back. An existing record under the same id is replaced;
/// leftover chunks from a longer previous record are removed.
pub(crate) fn put_blob(store: &dyn CredentialStore, id: &str, bytes: &[u8]) -> Result<()> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| Error::Invalid("invalid server credential reference".into()))?;
    if bytes.len() > MAX_BYTES {
        return Err(Error::Invalid("credential record exceeds 1 MiB".into()));
    }
    let previous_chunks = manifest(store, id).map(|m| m.chunks).unwrap_or(0);
    let chunks = bytes.len().div_ceil(CHUNK_BYTES).max(1);
    let result = (|| {
        for index in 0..chunks {
            let chunk = &bytes[(index * CHUNK_BYTES).min(bytes.len())
                ..((index + 1) * CHUNK_BYTES).min(bytes.len())];
            store.set(&format!("{id}/{index}"), chunk)?;
        }
        store.set(
            id,
            &serde_json::to_vec(&Manifest {
                chunks,
                digest: Sha256::digest(bytes).to_vec(),
            })?,
        )?;
        if get_blob(store, id)? != bytes {
            return Err(unavailable());
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            for index in chunks..previous_chunks {
                let _ = store.delete(&format!("{id}/{index}"));
            }
            Ok(())
        }
        Err(err) => {
            if previous_chunks == 0 {
                for index in 0..chunks {
                    let _ = store.delete(&format!("{id}/{index}"));
                }
                let _ = store.delete(id);
            }
            Err(err)
        }
    }
}

pub(crate) fn resolve(
    store: &dyn CredentialStore,
    config: &ServerConfig,
) -> Result<LaunchSettings> {
    let Some(id) = &config.credential_ref else {
        return Ok(LaunchSettings {
            args: config.args.clone(),
            env: config.env.clone(),
            headers: config.headers.clone(),
        });
    };
    if has_plaintext(config) {
        return Err(Error::Invalid(
            "server contains both credential references and plaintext launch values".into(),
        ));
    }
    serde_json::from_slice(&get_blob(store, id)?).map_err(|_| unavailable())
}

/// Verify every write before removing any plaintext from the in-memory config.
pub(crate) fn protect_server(store: &dyn CredentialStore, server: &mut ServerConfig) -> Result<()> {
    if let Some(id) = &server.credential_ref {
        uuid::Uuid::parse_str(id)
            .map_err(|_| Error::Invalid("invalid server credential reference".into()))?;
        if has_plaintext(server) {
            return Err(Error::Invalid(
                "server contains both credential references and plaintext launch values".into(),
            ));
        }
        // Already migrated: resolve at server startup. A missing credential should mark
        // that server failed, while leaving the panel available to remove/re-add it.
        return Ok(());
    }
    if !has_plaintext(server) {
        return Ok(());
    }
    let settings = LaunchSettings {
        args: server.args.clone(),
        env: server.env.clone(),
        headers: server.headers.clone(),
    };
    let bytes = serde_json::to_vec(&settings)?;
    let id = uuid::Uuid::new_v4().to_string();
    put_blob(store, &id, &bytes)?;
    let mut secured = server.clone();
    secured.credential_ref = Some(id.clone());
    secured.args.clear();
    secured.env.clear();
    secured.headers.clear();
    match resolve(store, &secured) {
        Ok(read_back) if read_back == settings => {
            *server = secured;
            Ok(())
        }
        _ => {
            let _ = delete(store, &id);
            Err(unavailable())
        }
    }
}

pub(crate) fn delete(store: &dyn CredentialStore, id: &str) -> Result<()> {
    let manifest = manifest(store, id)?;
    for chunk in 0..manifest.chunks {
        store.delete(&format!("{id}/{chunk}"))?;
    }
    store.delete(id)
}

/// Remove a record if present; a record that never existed is not an error.
pub(crate) fn delete_if_present(store: &dyn CredentialStore, id: &str) -> Result<()> {
    match manifest(store, id) {
        Ok(manifest) => {
            for chunk in 0..manifest.chunks {
                store.delete(&format!("{id}/{chunk}"))?;
            }
            store.delete(id)
        }
        Err(_) => store.delete(id),
    }
}

pub(crate) fn migrate(
    config: &PrismConfig,
    path: &std::path::Path,
    store: &dyn CredentialStore,
) -> Result<PrismConfig> {
    let mut secured = config.clone();
    let result = (|| {
        for server in &mut secured.servers {
            protect_server(store, server)?;
        }
        Ok::<_, Error>(())
    })();
    if let Err(err) = result {
        // New records only; an existing config's references must remain usable.
        for (old, new) in config.servers.iter().zip(&secured.servers) {
            if old.credential_ref.is_none() {
                if let Some(id) = &new.credential_ref {
                    let _ = delete(store, id);
                }
            }
        }
        return Err(err);
    }
    // Once a disk replacement has been attempted its outcome may be uncertain (for
    // example, directory fsync failed). Keep verified entries for recovery in that case.
    secured.save(path)?;
    Ok(secured)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    pub(crate) struct MemoryStore(pub Mutex<HashMap<String, Vec<u8>>>);
    impl CredentialStore for MemoryStore {
        fn set(&self, key: &str, value: &[u8]) -> Result<()> {
            self.0.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        fn get(&self, key: &str) -> Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(unavailable)
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    fn server() -> ServerConfig {
        ServerConfig {
            id: "server".into(),
            name: "test".into(),
            command: "echo".into(),
            args: vec!["--token=argument-secret".into()],
            env: BTreeMap::from([("CUSTOM_VALUE".into(), "env-secret".repeat(1000))]),
            enabled: false,
            credential_ref: None,
            url: None,
            auth: crate::config::HttpAuth::None,
            headers: Default::default(),
            oauth_ref: None,
            hidden_tools: Default::default(),
        }
    }

    #[test]
    fn migrates_plaintext_and_restores_chunked_launch_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prism.json");
        let original = PrismConfig {
            servers: vec![server()],
            ..Default::default()
        };
        std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
        let store = MemoryStore::default();
        migrate(&PrismConfig::load(&path).unwrap(), &path, &store).unwrap();
        let disk = std::fs::read_to_string(&path).unwrap();
        assert!(!disk.contains("argument-secret"));
        assert!(!disk.contains("env-secret"));
        let loaded = PrismConfig::load(&path).unwrap();
        let launch = resolve(&store, &loaded.servers[0]).unwrap();
        assert_eq!(launch.args, original.servers[0].args);
        assert_eq!(launch.env, original.servers[0].env);
        assert!(store
            .0
            .lock()
            .unwrap()
            .values()
            .all(|bytes| bytes.len() <= CHUNK_BYTES));
        let count = store.0.lock().unwrap().len();
        migrate(&loaded, &path, &store).unwrap();
        assert_eq!(
            store.0.lock().unwrap().len(),
            count,
            "migration is idempotent"
        );
        delete(&store, loaded.servers[0].credential_ref.as_ref().unwrap()).unwrap();
        assert!(store.0.lock().unwrap().is_empty());
    }

    #[test]
    fn unavailable_store_preserves_original_file_and_never_saves_plaintext() {
        struct Locked;
        impl CredentialStore for Locked {
            fn set(&self, _: &str, _: &[u8]) -> Result<()> {
                Err(unavailable())
            }
            fn get(&self, _: &str) -> Result<Vec<u8>> {
                Err(unavailable())
            }
            fn delete(&self, _: &str) -> Result<()> {
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prism.json");
        let config = PrismConfig {
            servers: vec![server()],
            ..Default::default()
        };
        let original = serde_json::to_vec(&config).unwrap();
        std::fs::write(&path, &original).unwrap();
        assert!(migrate(&config, &path, &Locked).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(config.save(&path).is_err());
    }

    #[test]
    fn failed_readback_preserves_plaintext_and_cleans_partial_credentials() {
        struct Corrupted(MemoryStore);
        impl CredentialStore for Corrupted {
            fn set(&self, key: &str, value: &[u8]) -> Result<()> {
                self.0.set(key, value)
            }
            fn get(&self, key: &str) -> Result<Vec<u8>> {
                if key.contains('/') {
                    Ok(b"corrupt".to_vec())
                } else {
                    self.0.get(key)
                }
            }
            fn delete(&self, key: &str) -> Result<()> {
                self.0.delete(key)
            }
        }
        let store = Corrupted(MemoryStore::default());
        let original = server();
        let mut candidate = original.clone();
        assert!(protect_server(&store, &mut candidate).is_err());
        assert_eq!(candidate, original);
        assert!(store.0 .0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn gateway_add_and_remove_protects_config_and_cleans_credentials() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prism.json");
        PrismConfig {
            listen_port: 0,
            ..Default::default()
        }
        .save(&path)
        .unwrap();
        let store = Arc::new(MemoryStore::default());
        let gateway = crate::Gateway::start_with_credentials(
            path.clone(),
            dir.path().join("audit.jsonl"),
            store.clone(),
        )
        .await
        .unwrap();
        let added = gateway.add_server(server()).await.unwrap();
        assert!(added.args.is_empty());
        assert!(added.env.is_empty());
        assert!(added.credential_ref.is_some());
        assert_eq!(resolve(store.as_ref(), &added).unwrap().args, server().args);
        let disk = std::fs::read_to_string(&path).unwrap();
        assert!(!disk.contains("argument-secret"));
        assert!(!disk.contains("env-secret"));
        gateway.remove_server(&added.id).await.unwrap();
        assert!(store.0.lock().unwrap().is_empty());
        assert!(PrismConfig::load(&path).unwrap().servers.is_empty());
        gateway.shutdown().await;
    }

    #[test]
    #[ignore = "requires an unlocked native OS credential store"]
    fn native_store_round_trip() {
        let store = NativeStore::default();
        let mut server = server();
        protect_server(&store, &mut server).unwrap();
        let id = server.credential_ref.as_ref().unwrap();
        let resolved = resolve(&store, &server);
        let removed = delete(&store, id);
        assert!(resolved.is_ok());
        removed.unwrap();
        assert!(resolve(&store, &server).is_err());
    }

    #[test]
    fn file_store_round_trip_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let cred_path = dir.path().join("credentials.json");

        // Write with first store instance
        {
            let store = FileStore::new(cred_path.clone()).unwrap();
            let mut server = server();
            let expected_args = server.args.clone();
            let expected_env = server.env.clone();
            protect_server(&store, &mut server).unwrap();
            assert!(server.credential_ref.is_some());
            let resolved = resolve(&store, &server).unwrap();
            assert_eq!(resolved.args, expected_args);
            assert_eq!(resolved.env, expected_env);
            assert!(cred_path.exists());
        }

        // Re-read with a new store instance (persistence check)
        {
            let store = FileStore::new(cred_path.clone()).unwrap();
            let mut server = server();
            // Assign the credential_ref from disk
            let disk_content = std::fs::read_to_string(&cred_path).unwrap();
            assert!(!disk_content.is_empty());
            // Lookup key from entries
            let id = store
                .entries
                .read()
                .unwrap()
                .keys()
                .find(|k| !k.contains('/'))
                .cloned()
                .unwrap();
            server.args.clear();
            server.env.clear();
            server.credential_ref = Some(id.clone());
            let resolved = resolve(&store, &server).unwrap();
            assert_eq!(resolved.args, vec!["--token=argument-secret"]);
            assert_eq!(
                resolved.env.get("CUSTOM_VALUE").unwrap(),
                &"env-secret".repeat(1000)
            );

            // Delete
            delete(&store, &id).unwrap();
            assert!(resolve(&store, &server).is_err());
        }
    }

    #[tokio::test]
    async fn gateway_starts_with_default_file_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prism.json");
        PrismConfig {
            listen_port: 0,
            ..Default::default()
        }
        .save(&path)
        .unwrap();

        // Gateway::start should create credentials.json next to prism.json
        let gateway = crate::Gateway::start(&path, dir.path().join("audit.jsonl"))
            .await
            .unwrap();
        let cred_path = path.with_file_name("credentials.json");

        let added = gateway.add_server(server()).await.unwrap();
        assert!(added.credential_ref.is_some());
        assert!(cred_path.exists());
        gateway.shutdown().await;
    }
}

