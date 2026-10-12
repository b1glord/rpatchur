//! Optional, fail-closed regional identity and THOR allowlist for deployments.
//! A SHA256 manifest is not a signature: operators must protect local JSON/config.
use crate::config::{PatcherConfiguration, RegionalGuardConfig};
use crate::thor::{ThorArchive, ThorPatchList};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Deserialize)]
struct RegionalManifest {
    schema: String,
    profile_id: String,
    region: String,
    channel: String,
    client_exe_sha256: String,
    target_grf: String,
    patches: Vec<ApprovedPatch>,
}

#[derive(Deserialize)]
struct ApprovedPatch {
    index: usize,
    file_name: String,
    sha256: String,
}

pub struct RegionGuard {
    profile_id: String,
    manifest_digest: String,
    grf_name: String,
    checksums: HashMap<usize, (String, String)>,
}

fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 240
        && !s.starts_with('.')
        && !s.ends_with(' ')
        && !s.contains("..")
        && s.bytes().all(|c| {
            c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.' || c == b' '
        })
}

fn safe_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 &&
        s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn valid_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest_read<R: Read + Seek>(input: &mut R) -> Result<String, String> {
    input.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut sha = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let n = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        sha.update(&buffer[..n]);
    }
    input.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", sha.finalize()))
}

fn safe_thor_path(s: &str) -> bool {
    if s.is_empty() || s.starts_with('/') || s.starts_with('\\') || s.contains(':') {
        return false;
    }
    s.split(|c| c == '/' || c == '\\').all(|component| {
        !component.is_empty() && component != "." && component != ".." &&
        !component.contains('\0') && !component.chars().any(|c| c.is_control())
    })
}

impl RegionGuard {
    pub fn load(config: &PatcherConfiguration) -> Result<Option<Self>, String> {
        let policy = match config.patching.compatibility_guard.as_ref() {
            Some(v) => v,
            None => return Ok(None),
        };
        Self::from_policy(config, policy).map(Some)
    }

    fn from_policy(config: &PatcherConfiguration, policy: &RegionalGuardConfig)
        -> Result<Self, String>
    {
        if !safe_id(&policy.profile_id) || !safe_name(&policy.manifest_file)
            || !policy.manifest_file.ends_with(".json")
            || !safe_name(&config.play.path)
            || !safe_name(&config.client.default_grf_name)
            || !valid_sha(&policy.client_exe_sha256)
        {
            return Err("Invalid regional profile/manifest/client/GRF identity".into());
        }
        match (policy.region.as_str(), policy.channel.as_str()) {
            ("levelupgt", "custom") | ("kro", "main") | ("kro", "sakray")
            | ("iro", "main") | ("iro", "sakray") => {}
            _ => return Err("Unsupported regional/channel combination".into())
        };
        let bytes = std::fs::read(&policy.manifest_file)
            .map_err(|e| format!("Cannot load protected regional manifest: {}", e))?;
        if bytes.len() > 2_000_000 {
            return Err("Regional manifest exceeds size limit".into());
        }
        let manifest: RegionalManifest = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Invalid protected regional manifest: {}", e))?;
        if manifest.schema != "levelupgt.rpatchur-region-manifest.v1"
            || manifest.profile_id != policy.profile_id
            || manifest.region != policy.region
            || manifest.channel != policy.channel
            || !manifest.client_exe_sha256.eq_ignore_ascii_case(&policy.client_exe_sha256)
            || manifest.target_grf != config.client.default_grf_name
        {
            return Err("Manifest has wrong region, channel, EXE or target GRF".into());
        }
        let mut client = File::open(&config.play.path)
            .map_err(|e| format!("Missing verified game executable: {}", e))?;
        let real_sha = digest_read(&mut client)?;
        if !real_sha.eq_ignore_ascii_case(&policy.client_exe_sha256) {
            return Err("Game EXE SHA256 does not match protected profile".into());
        }
        if manifest.patches.is_empty() || manifest.patches.len() > 4096 {
            return Err("Regional manifest must have 1-4096 approved THOR patches".into());
        }
        let mut checksums = HashMap::new();
        let mut names = HashSet::new();
        for patch in manifest.patches {
            if !safe_name(&patch.file_name)
                || !patch.file_name.to_ascii_lowercase().ends_with(".thor")
                || !valid_sha(&patch.sha256)
                || !names.insert(patch.file_name.to_ascii_lowercase())
                || checksums.insert(
                    patch.index,
                    (patch.file_name.clone(), patch.sha256.to_ascii_lowercase())
                ).is_some()
            {
                return Err("Manifest contains ambiguous or unsafe patch identity".into());
            }
        }
        Ok(Self {
            profile_id: policy.profile_id.clone(),
            manifest_digest: digest_bytes(&bytes),
            grf_name: manifest.target_grf,
            checksums,
        })
    }

    pub fn validate_list(&self, list: &ThorPatchList) -> Result<(), String> {
        if list.is_empty() { return Err("Guarded patch list is empty".into()); }
        let mut seen = HashSet::new();
        for patch in list {
            self.validate_patch(patch.index, &patch.file_name)?;
            if !seen.insert(patch.index) {
                return Err("Duplicate patch index in server plist".into());
            }
        }
        Ok(())
    }

    pub fn validate_patch(&self, index: usize, file_name: &str) -> Result<(), String> {
        if !safe_name(file_name) || !file_name.to_ascii_lowercase().ends_with(".thor") {
            return Err("Unsafe patch filename".into());
        }
        match self.checksums.get(&index) {
            Some((expected, _)) if expected == file_name => Ok(()),
            _ => Err(format!("Patch not approved for this region: {} / {}", index, file_name))
        }
    }

    pub fn validate_bytes<R: Read + Seek>(&self, index: usize, name: &str, input: &mut R)
        -> Result<(), String>
    {
        self.validate_patch(index, name)?;
        let digest = digest_read(input)?;
        if digest != self.checksums[&index].1 {
            return Err(format!("Wrong downloaded THOR SHA256 for: {}", name));
        }
        Ok(())
    }

    pub fn validate_target(&self, name: &str) -> Result<(), String> {
        if name == self.grf_name && safe_name(name) { Ok(()) }
        else { Err("THOR attempts to target a GRF outside approved profile".into()) }
    }

    pub fn validate_archive<R: Read + Seek>(&self, archive: &ThorArchive<R>) -> Result<(), String> {
        for entry in archive.get_entries() {
            if !safe_thor_path(&entry.relative_path) {
                return Err("THOR archive contains unsafe extracted path".into());
            }
        }
        Ok(())
    }

    pub fn cache_name(&self, patcher_name: &str) -> String {
        // Never reuse the unscoped legacy .dat cache between client profiles.
        format!("{}.{}.{}.dat", patcher_name, self.profile_id, &self.manifest_digest[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thor::ThorPatchInfo;
    use std::io::Cursor;

    fn sample() -> RegionGuard {
        RegionGuard {
            profile_id: "levelupgt-20220406".to_owned(),
            manifest_digest: "b".repeat(64),
            grf_name: "ragnardata.grf".to_owned(),
            checksums: HashMap::from([
                (22, ("skin-Phieti Renewal.thor".to_owned(), digest_bytes(b"good patch")))
            ]),
        }
    }

    #[test]
    fn fail_closed_wrong_region_path_and_modified_bytes() {
        let g = sample();
        assert!(g.validate_patch(22, "skin-Phieti Renewal.thor").is_ok());
        assert!(g.validate_patch(22, "kro-sakray.thor").is_err());
        assert!(g.validate_patch(22, "../skin-Phieti Renewal.thor").is_err());
        assert!(g.validate_target("data.grf").is_err());
        assert!(g.validate_target("ragnardata.grf").is_ok());
        assert!(g.validate_bytes(22, "skin-Phieti Renewal.thor", &mut Cursor::new(b"good patch")).is_ok());
        assert!(g.validate_bytes(22, "skin-Phieti Renewal.thor", &mut Cursor::new(b"tampered")).is_err());
        assert!(!safe_thor_path(r"data\..\ragnardata.grf"));
        assert!(safe_thor_path(r"data\texture\ok.bmp"));
    }

    #[test]
    fn list_validation_rejects_unknown_and_duplicate_index() {
        let g = sample();
        let items = vec![
            ThorPatchInfo { index:22, file_name:"skin-Phieti Renewal.thor".into() },
            ThorPatchInfo { index:22, file_name:"skin-Phieti Renewal.thor".into() },
        ];
        assert!(g.validate_list(&items).is_err());
    }

    #[test]
    fn guarded_cache_cannot_reuse_legacy_cache_name() {
        let g = sample();
        assert_eq!(g.cache_name("rpatchur"), "rpatchur.levelupgt-20220406.bbbbbbbbbbbbbbbb.dat");
    }
}
