# Native rPatchur region/channel patch protection

This is an **opt-in, default-off** security layer. The existing 2015
configuration remains compatible because `patching.compatibility_guard`
is optional. **Default-off is unprotected**, not certified.

For new or migrated Ragnarok deployments, the guard validates:

1. Profile ID, region and channel (`levelupgt/custom`, `kro/main`,
   `kro/sakray`, `iro/main`, `iro/sakray`)
2. The actual executable referenced by `play.path`, using SHA-256
3. Locally protected JSON manifest of patch list indices, names and
   exact downloaded THOR byte SHA-256 values
4. Every *unfiltered* remote plist entry, before consulting cache,
   and before patch downloads
5. Target GRF filename and every THOR archive relative path before
   any GRF or loose-file modification

When protection is active, HTTP plist and patch URLs are refused.
A changed manifest gets a different scoped cache filename; the old
legacy `rpatchur.dat` is never reused across guarded profiles.
A new manifest can cause earlier patches to be reapplied; test this
in an **isolated clean client** before enabling on real installations.

Example addition to `rpatchur.json`:

```json
"patching": {
  "in_place": false,
  "compatibility_guard": {
    "profile_id": "levelupgt-renewal-20220406",
    "region": "levelupgt",
    "channel": "custom",
    "client_exe_sha256": "<verified-sha256-of-game-exe>",
    "manifest_file": "regional-patches.json"
  }
}
```

The `regional-patches.json` in the protected working directory:

```json
{
  "schema": "levelupgt.rpatchur-region-manifest.v1",
  "profile_id": "levelupgt-renewal-20220406",
  "region": "levelupgt",
  "channel": "custom",
  "client_exe_sha256": "<verified-sha256-of-game-exe>",
  "target_grf": "ragnardata.grf",
  "patches": [
    {
      "index": 22,
      "file_name": "skin-Phieti Renewal.thor",
      "sha256": "<verified-sha256-of-thor>"
    }
  ]
}
```

The angle-bracketed values are **invalid placeholders**. Never replace
them with guessed hashes or distribute this example as live config.

### Current release position

- Existing public root `b1glord/ragnarokclientpatch` aliases
  **2015** and must not be repointed.
- The **2022** channel is `candidate-audit`, `ready=false` and
  has zero published patches. No production enablement is authorized.
- No verified 20220406 clean EXE/GRF or confirmed S2 gameplay/login
  evidence has been supplied by this change.
- An EXE digest and patch checksums are **not publisher signatures**.
  An attacker who can edit the config and manifest can substitute both.
  Lock down their permissions, use a trusted update origin, and add a
  signed manifest before untrusted production distribution.
- GRF filename is checked, but current GRF binary contents are not
  rehashed after every update. The existing in-place GRF method can
  corrupt the installation on failure; prefer out-of-place and backups.
- Existing Thor plist entries whose filename contains spaces are now
  parsed as a single name, including `skin-Phieti Renewal.thor`.
- Rust format, compile and tests must pass; do not merge this draft PR
  as proof of an installer or live-client success.

References:
- [RagnarokClient patch preflight](https://github.com/LevelUpGT/RagnarokClient/pull/5)
- [BEAM patch guard](https://github.com/LevelUpGT/beam-patcher/pull/5)
- [Public patch channels](https://github.com/b1glord/ragnarokclientpatch)
