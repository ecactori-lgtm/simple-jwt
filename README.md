# JWT Workbench

A small local JWT generator: vanilla HTML/CSS/JavaScript in the browser and a TypeScript server using Node's built-in HTTP module. `jose` handles HS256 signing. No framework, database, external requests, or browser storage.

## Run

Requires Node.js 22.12 or newer.

```sh
npm install
npm run dev
```

Open **http://localhost:3000**. Enter optional subject, issuer, and audience; choose an expiration; add a JSON object of custom claims; and enter or generate a signing secret. Click **Generate token**, then **Copy token**. The generated token's header and payload are shown alongside it.

The development server restarts when server code changes. Refresh the browser after editing frontend files.

```sh
npm run verify  # Type checking, API/signature tests, and compilation
npm run build
npm start      # Run compiled server; keep public/ alongside dist/
```

Set `PORT` to change the listening port, for example `PORT=3001 npm run dev`.

## API

`POST /api/tokens` with `Content-Type: application/json`:

```json
{
  "subject": "user_123",
  "issuer": "my-app",
  "audience": "my-api",
  "expiresIn": 3600,
  "claims": { "role": "developer" },
  "secret": "<your randomly generated secret of at least 32 UTF-8 bytes>"
}
```

Returns `{ token, header, payload, expiresAt }`. `expiresAt`, `iat`, and `exp` are Unix timestamps in seconds. `expiresIn` is required and accepts integer seconds from 60 to 604800. `secret` is required and accepts 32–4096 UTF-8 bytes, used literally as text (not base64/hex decoded). All other fields are optional. Custom claims must be a JSON object and cannot override `sub`, `iss`, `aud`, `iat`, `exp`, or `nbf`. Request bodies are limited to 16 KB, and generation is limited to 60 requests per minute per server instance.

## Local development scope

The server binds to `127.0.0.1`, accepts only local hostnames, and rejects browser requests from other origins. This is a developer utility that signs arbitrary claims with a user-supplied key; it is not an authentication or token issuance service. Add authentication and an authorization policy before adapting it for a shared service.

Secrets and tokens are not persisted or logged by the application. They are sent to your local server and remain in page memory until edited or reloaded; copying a token puts it on your system clipboard. Generated secrets use the browser's cryptographic random generator. JWT payloads are readable by anyone holding the token, so avoid sensitive claims and use disposable development secrets.
