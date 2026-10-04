# Optional Hermes integration

The plugin requires a compatible Hermes gateway with `gateway.session_context`.
The synthetic tests verify the gateway contract. A pinned live gateway version still needs acceptance testing.

1. Keep the plugin directory and its `plugin.yaml` together when installing it with Hermes' plugin mechanism.
2. Initialize a **new** explicit journal path with `initializeHermesMemoryStore({ dbPath })`.
   Use a private directory (mode `0700`); the database must have mode `0600`.
3. Create a local JSON config with mode `0600`. Set `HERMES_MEMPALACE_CONFIG` to its absolute path.
   Replace every path and synthetic route below with your own local values.
4. Let the gateway supply trusted session context. Do not accept profile, chat, user or session identity from model arguments.
5. Ask the model to propose a write. Review the proposal text, ID and hash.
   Send the exact `/memory-confirm ID HASH` command in the same private chat and session before it expires.

```json
{
  "schemaVersion": 1,
  "nodeCommand": "/absolute/path/to/node",
  "serverPath": "/absolute/path/to/memory-ledger/scripts/hermes_mempalace_mcp.js",
  "dbPath": "/absolute/private-directory/events.sqlite3",
  "proposalTtlSeconds": 300,
  "routes": [
    { "profile": "example", "chatId": "1001", "userId": "1001" }
  ]
}
```

The numbers are synthetic. Only configured private owner chats are accepted.
The gateway sets `HERMES_MEMPALACE_CONTEXT_B64` for each bridge process from its trusted context.
The model-facing tools are `mempalace_context` and `mempalace_propose_write`.
There is no model-facing confirmation tool.
The confirmation checks the exact proposal hash, owner, topic, session and expiry.
A consumed proposal cannot be replayed. The configured lifetime must be 30–300 seconds.

Never commit the local config, session environment or database. The main README explains default database paths and privacy limits.
