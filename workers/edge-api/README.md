# Nexus edge API

The public edge API requires HTTPS by default in every environment. For local Wrangler development
only, copy `.dev.vars.example` to the ignored `.dev.vars` file. This opts `http://localhost` and
`http://127.0.0.1` requests into the shared HTTPS guard's local exception.

Do not configure `ALLOW_LOCALHOST_HTTP` in preview, staging, or production. Even when the flag is
enabled, plain HTTP requests to non-local hosts remain rejected.
