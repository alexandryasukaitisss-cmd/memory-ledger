# Setup, upgrades and data lifetime

Start with `npm run demo`. It uses synthetic temporary stores.
For an integration, always pass a new absolute `dbPath` to `openMemoryStore({ dbPath })`.
Keep its directory private. Journal writes preserve prior events; there is no automatic expiry.
The caller owns retention decisions. Deleting events can break evidence links and history.

## Backup and restore

The operator tools require explicit absolute paths. They never use the working-memory default.
Create the destination directory first. On macOS/Linux, it must have mode `0700`.
On Windows, configure a private directory with Windows access controls before using these tools.
Backups and exports contain raw memory, including possible personal data.

```sh
mkdir -m 700 /absolute/private-backups
python3 tools/journal.py backup --db /absolute/private/events.sqlite3 --to /absolute/private-backups/backup.sqlite3
python3 tools/journal.py restore --db /absolute/private-backups/backup.sqlite3 --to /absolute/private-backups/restored.sqlite3
python3 tools/journal.py export --db /absolute/private/events.sqlite3 --to /absolute/private-backups/events.jsonl
```

On Windows, use `python` if `python3` is unavailable.
SQLite online backup includes committed writes in the write-ahead log.
Restore creates a new database and refuses to overwrite a file or symbolic link.
An export contains raw journal events, not every Wiki table. It cannot replace a database backup.
`--before 2025-01-01T00:00:00Z` selects earlier capture timestamps for export; it never deletes them.
Neither tool is exposed to model-facing Hermes tools.

## Upgrade an integration

1. Stop writers in your integration and back up **both** the journal and Wiki databases.
2. Record the package commit and test the new version against disposable restored copies.
3. Run `npm test` and your integration's current/history/approval checks.
4. Switch the integration only after those checks pass.

The modules validate and migrate supported schema versions when opening a writable store.
Older code rejects a newer unsupported schema. Rollback requires the old package and its matching backup.
There is no unattended updater or destructive migration command in this package.

Hermes requires POSIX file permissions and a compatible gateway. Its live installation is still unverified.
The Windows CI job checks the portable journal, lineage and Node/Python contracts; it does not certify Hermes or the privacy of Windows file access controls. POSIX mode checks run on Linux and macOS; Windows users must configure private ACLs for the database, exports and HMAC key.
