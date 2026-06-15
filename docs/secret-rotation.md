# Credential key rotation (F-34)

Device credentials (API keys, OAuth2 client secrets) are encrypted at rest with a
Fernet key — in SQLite (embedded mode) and in Redis (distributed mode). F-34 lets
you **rotate that key with zero downtime**: no window where credentials are
unreadable and no big-bang re-encrypt that must complete before the service can
serve.

## How it works

The codec accepts **multiple keys** (Fernet `MultiFernet`). The **first key is
primary** — it encrypts every new write; **all** keys can decrypt. So during a
rotation the running gateway/workers transparently read credentials written under
the old key while writing new ones under the new key.

Keys are resolved (highest precedence first):

1. `MCP_SECRET_KEY` env — may carry several keys, comma- or space-separated:
   `MCP_SECRET_KEY="<new>,<old>"`
2. `gateway.secret_keys` — a YAML list, new key first
3. `gateway.secret_key` — the legacy single key

A single key behaves exactly as before this feature.

## Rotating a key

```
# 1. Generate a new key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**2. Deploy with both keys, new one first.** Every gateway and worker must carry
both keys before anything is re-encrypted, so the whole fleet can still decrypt
old ciphertext:

```yaml
gateway:
  secret_keys:
    - "<new-key>"   # primary — encrypts new writes
    - "<old-key>"   # still decrypts existing credentials
```

or `MCP_SECRET_KEY="<new-key>,<old-key>"`. New writes are now encrypted with the
new key; existing rows are still readable. **The service is fully functional at
this point** — you can stop here and let new writes migrate naturally, or
continue to actively re-encrypt everything so the old key can be retired.

**3. Re-encrypt stored credentials** under the new key:

```
device-mcp-rotate-secrets --config config.yaml
```

It picks the storage path from `registry.mode` (SQLite for embedded, Redis for
distributed), re-encrypts every credential under the primary key, and prints a
summary:

```
Rotation complete (distributed mode): 12 credential(s): 9 rotated, 3 already current, 0 failed
```

The pass is **idempotent** (re-runnable) and **loss-free**: a credential that no
configured key can decrypt is reported (`failed`, non-zero exit) and left
**untouched** rather than dropped, so a missing old key is a visible error you can
fix, not silent data loss. Run it once per stack (it operates on the shared
store/registry, not per-replica).

**4. Retire the old key.** Once the pass reports `0 failed` and all credentials
are `rotated`/`already current`, redeploy with only the new key:

```yaml
gateway:
  secret_keys:
    - "<new-key>"
```

## Operational notes

- **Run the pass against the same storage the gateway uses.** In distributed mode
  it connects to Redis (and honours the F-24 Redis-auth gate); in embedded mode it
  opens the SQLite DB at `storage.db_path`. Run it from a pod/host with that access.
- **`failed > 0`** means some ciphertext couldn't be decrypted by any configured
  key — you removed the old key too early, or a record predates a key you no
  longer have. Add the missing key back and re-run; the failed records are intact.
- **Startup log.** With more than one key configured the gateway logs
  `Credential encryption enabled (key rotation in progress: True)` — a reminder
  that a rotation window is open and the old key has not yet been retired.
- The encryption key protects credentials **at rest**. Rotating it does not change
  the device-side credentials themselves; to rotate an actual API key/secret,
  update the device registration (which re-encrypts under the current primary key).
