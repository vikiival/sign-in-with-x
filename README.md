# Sign in with X using Cloudflare Workers + Hono

## Development
```txt
pnpm install
pnpm run dev
```

Deploy with Wrangler when ready:
```txt
pnpm run deploy
```

Generate type definitions for Wrangler bindings (optional but recommended):
```txt
pnpm run cf-typegen
```

## Environment configuration
Set the following secrets in your Worker environment (e.g. with `wrangler secret put`):

- `TWITTER_CLIENT_ID`
- `TWITTER_CLIENT_SECRET`
- `TWITTER_REDIRECT_URI` – must match the callback URL registered with X
- `TWITTER_SCOPE` *(optional)* – defaults to `tweet.read users.read offline.access`

## OAuth flow
The Worker exposes two routes:

- `GET /auth/x` – generates PKCE values, stores them in secure cookies, and redirects to the X authorization page
- `GET /auth/x/callback` – validates the state, exchanges the authorization code for tokens, and returns the tokens plus the signed-in user's profile (when available)

Pass the `CloudflareBindings` type when instantiating Hono so Wrangler-generated bindings stay in sync:
```ts
const app = new Hono<{ Bindings: CloudflareBindings }>()
```
