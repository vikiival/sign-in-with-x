import { Hono } from 'hono'
import type { Context } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import { cors } from 'hono/cors'

interface Bindings {
  TWITTER_CLIENT_ID: string
  TWITTER_CLIENT_SECRET: string
  TWITTER_REDIRECT_URI: string
  TWITTER_SCOPE?: string
  APP_REDIRECT_URL?: string
  APP_ORIGIN?: string
}

type HonoEnv = {
  Bindings: Bindings
}

declare global {
  // Wrangler will merge this with its generated bindings interface
  interface CloudflareBindings extends Bindings {}
}

const app = new Hono<HonoEnv>()

const DEFAULT_SCOPE =
  'tweet.read users.read offline.access' satisfies string

const COOKIE_STATE = 'x_oauth_state'
const COOKIE_VERIFIER = 'x_oauth_verifier'
const COOKIE_ACCESS_TOKEN = 'x_access_token'
const COOKIE_REFRESH_TOKEN = 'x_refresh_token'

const TOKEN_URL = 'https://api.twitter.com/2/oauth2/token'
const DEFAULT_APP_REDIRECT = 'https://feat-mint-card.app-bzd.pages.dev/card'

const STATE_COOKIE_OPTIONS = {
  secure: true,
  httpOnly: true,
  sameSite: 'Lax' as const,
  path: '/',
  maxAge: 600,
}

const AUTH_COOKIE_OPTIONS = {
  secure: true,
  httpOnly: true,
  sameSite: 'None' as const,
  path: '/',
}

type TokenResponse = {
  token_type: string
  access_token: string
  expires_in: number
  scope: string
  refresh_token?: string
}

const textEncoder = new TextEncoder()

const toBase64Url = (buffer: ArrayBuffer) => {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

const randomBase64Url = (size = 32) => {
  const array = new Uint8Array(size)
  crypto.getRandomValues(array)
  return toBase64Url(array.buffer)
}

const sha256Base64Url = async (value: string) => {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))
  return toBase64Url(digest)
}

const buildBasicAuthHeader = (clientId: string, clientSecret: string) =>
  `Basic ${btoa(`${clientId}:${clientSecret}`)}`

const setAuthCookies = (c: Context<HonoEnv>, tokens: TokenResponse) => {
  setCookie(c, COOKIE_ACCESS_TOKEN, tokens.access_token, {
    ...AUTH_COOKIE_OPTIONS,
    maxAge: tokens.expires_in,
  })

  if (tokens.refresh_token) {
    setCookie(c, COOKIE_REFRESH_TOKEN, tokens.refresh_token, {
      ...AUTH_COOKIE_OPTIONS,
      maxAge: 60 * 60 * 24 * 30,
    })
  }
}

const clearAuthCookies = (c: Context<HonoEnv>) => {
  setCookie(c, COOKIE_ACCESS_TOKEN, '', { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })
  setCookie(c, COOKIE_REFRESH_TOKEN, '', { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })
}

const refreshAccessToken = async (
  c: Context<HonoEnv>,
  refreshToken: string,
): Promise<TokenResponse | null> => {
  const { TWITTER_CLIENT_ID, TWITTER_CLIENT_SECRET, TWITTER_REDIRECT_URI } = c.env

  if (!TWITTER_CLIENT_ID || !TWITTER_CLIENT_SECRET) {
    return null
  }

  const tokenBody = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: TWITTER_CLIENT_ID,
  })

  if (TWITTER_REDIRECT_URI) {
    tokenBody.set('redirect_uri', TWITTER_REDIRECT_URI)
  }

  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: buildBasicAuthHeader(
        TWITTER_CLIENT_ID,
        TWITTER_CLIENT_SECRET,
      ),
    },
    body: tokenBody.toString(),
  })

  if (!response.ok) {
    return null
  }

  const tokens = (await response.json().catch(() => null)) as TokenResponse | null

  if (!tokens || !tokens.access_token) {
    return null
  }

  setAuthCookies(c, tokens)
  return tokens
}

const ensureAccessToken = async (c: Context<HonoEnv>): Promise<string | null> => {
  const accessToken = getCookie(c, COOKIE_ACCESS_TOKEN)
  if (accessToken) {
    return accessToken
  }

  const refreshToken = getCookie(c, COOKIE_REFRESH_TOKEN)
  if (!refreshToken) {
    return null
  }

  const tokens = await refreshAccessToken(c, refreshToken)
  return tokens?.access_token ?? null
}

const resolveAppOrigin = (env: Bindings) => {
  if (env.APP_ORIGIN) {
    return env.APP_ORIGIN
  }

  const target = env.APP_REDIRECT_URL ?? DEFAULT_APP_REDIRECT

  try {
    return new URL(target).origin
  } catch {
    return new URL(DEFAULT_APP_REDIRECT).origin
  }
}

app.get('/', (c) => c.text('Sign in with X ready'))

app.get('/auth/x', async (c) => {
  const { TWITTER_CLIENT_ID, TWITTER_REDIRECT_URI, TWITTER_SCOPE } = c.env

  if (!TWITTER_CLIENT_ID || !TWITTER_REDIRECT_URI) {
    return c.json(
      { message: 'Missing required X OAuth configuration' },
      500,
    )
  }

  clearAuthCookies(c)

  const state = randomBase64Url(16)
  const codeVerifier = randomBase64Url(48)
  const codeChallenge = await sha256Base64Url(codeVerifier)

  const authorizeUrl = new URL('https://twitter.com/i/oauth2/authorize')
  authorizeUrl.searchParams.set('response_type', 'code')
  authorizeUrl.searchParams.set('client_id', TWITTER_CLIENT_ID)
  authorizeUrl.searchParams.set('redirect_uri', TWITTER_REDIRECT_URI)
  authorizeUrl.searchParams.set('scope', TWITTER_SCOPE ?? DEFAULT_SCOPE)
  authorizeUrl.searchParams.set('state', state)
  authorizeUrl.searchParams.set('code_challenge', codeChallenge)
  authorizeUrl.searchParams.set('code_challenge_method', 'S256')

  setCookie(c, COOKIE_STATE, state, STATE_COOKIE_OPTIONS)
  setCookie(c, COOKIE_VERIFIER, codeVerifier, STATE_COOKIE_OPTIONS)

  return c.redirect(authorizeUrl.toString(), 302)
})

app.get('/auth/x/callback', async (c) => {
  const { TWITTER_CLIENT_ID, TWITTER_CLIENT_SECRET, TWITTER_REDIRECT_URI } = c.env
  const url = new URL(c.req.url)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  const error = url.searchParams.get('error')

  if (error) {
    return c.json({ message: 'X authorization failed', error }, 400)
  }

  if (!code || !state) {
    return c.json({ message: 'Missing code or state' }, 400)
  }

  const savedState = getCookie(c, COOKIE_STATE)
  const codeVerifier = getCookie(c, COOKIE_VERIFIER)

  if (!savedState || savedState !== state || !codeVerifier) {
    return c.json({ message: 'Invalid or expired authorization state' }, 400)
  }

  if (!TWITTER_CLIENT_ID || !TWITTER_CLIENT_SECRET || !TWITTER_REDIRECT_URI) {
    return c.json(
      { message: 'Missing required X OAuth configuration' },
      500,
    )
  }

  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    redirect_uri: TWITTER_REDIRECT_URI,
    code,
    code_verifier: codeVerifier,
  })

  const tokenResponse = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: buildBasicAuthHeader(
        TWITTER_CLIENT_ID,
        TWITTER_CLIENT_SECRET,
      ),
    },
    body: tokenBody.toString(),
  })

  if (!tokenResponse.ok) {
    const payload = await tokenResponse.json().catch(() => undefined)
    return c.json(
      {
        message: 'Failed to exchange authorization code',
        error: payload ?? tokenResponse.statusText,
      },
      502,
    )
  }

  const tokens = (await tokenResponse.json()) as TokenResponse

  setAuthCookies(c, tokens)

  let profile: unknown = null
  try {
    const profileResponse = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url', {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
    })

    if (profileResponse.ok) {
      profile = await profileResponse.json()
    }
  } catch (profileError) {
    console.warn('Failed to fetch X profile', profileError)
  }

  const expiredStateCookieOptions = { ...STATE_COOKIE_OPTIONS, maxAge: 0 }
  setCookie(c, COOKIE_STATE, '', expiredStateCookieOptions)
  setCookie(c, COOKIE_VERIFIER, '', expiredStateCookieOptions)

  const redirectTarget = c.env.APP_REDIRECT_URL ?? DEFAULT_APP_REDIRECT
  let redirectUrl: URL

  try {
    redirectUrl = new URL(redirectTarget)
  } catch (parseError) {
    console.warn('Invalid APP_REDIRECT_URL provided, falling back to default', parseError)
    redirectUrl = new URL(DEFAULT_APP_REDIRECT)
  }

  // Provide safe profile data for the frontend; sensitive tokens stay in cookies
  if (profile && typeof profile === 'object' && 'data' in profile) {
    const userData = profile.data as Record<string, unknown>
    const userId = typeof userData.id === 'string' ? userData.id : undefined
    const username = typeof userData.username === 'string' ? userData.username : undefined
    const name = typeof userData.name === 'string' ? userData.name : undefined
    const imageUrl = typeof userData.profile_image_url === 'string' ? userData.profile_image_url : undefined

    if (userId) redirectUrl.searchParams.set('user_id', userId)
    if (username) redirectUrl.searchParams.set('username', username)
    if (name) redirectUrl.searchParams.set('name', name)
    if (imageUrl) redirectUrl.searchParams.set('profile_image_url', imageUrl)
  }

  return c.redirect(redirectUrl.toString(), 302)
})

const mintCors = cors({
  origin: (_origin, context) => resolveAppOrigin(context.env),
  allowMethods: ['POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
  credentials: true,
})

app.use('/auth/mint', mintCors)

app.post('/auth/mint', async (c) => {
  const accessToken = await ensureAccessToken(c)

  if (!accessToken) {
    clearAuthCookies(c)
    return c.json({ message: 'Not signed in with X' }, 401)
  }

  let body: unknown
  try {
    body = await c.req.json()
  } catch {
    return c.json({ message: 'Invalid request body' }, 400)
  }

  if (!body || typeof body !== 'object') {
    return c.json({ message: 'Invalid request body' }, 400)
  }

  const { address, imageUrl, description } = body as Record<string, unknown>

  if (typeof address !== 'string' || !address) {
    return c.json({ message: 'Wallet address is required' }, 400)
  }

  try {
    const profileResponse = await fetch('https://api.twitter.com/2/users/me?user.fields=public_metrics', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (profileResponse.status === 401) {
      clearAuthCookies(c)
      return c.json({ message: 'X session expired, please sign in again' }, 401)
    }

    if (!profileResponse.ok) {
      return c.json(
        {
          message: 'Failed to fetch user profile',
          error: profileResponse.statusText,
        },
        502,
      )
    }

    const profile = (await profileResponse.json()) as {
      data?: {
        id?: string
        name?: string
        username?: string
        public_metrics?: {
          followers_count?: number
        }
      }
    }

    if (!profile?.data?.username) {
      return c.json({ message: 'Unable to read X profile data' }, 502)
    }

    const followers = profile.data.public_metrics?.followers_count ?? 0

    const claimResponse = await fetch('https://waifu-me.kodadot.workers.dev/cards/verychaoticksm/claim', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        displayName: profile.data.name ?? profile.data.username,
        username: profile.data.username,
        address,
        imageUrl: typeof imageUrl === 'string' ? imageUrl : undefined,
        description: typeof description === 'string' ? description : undefined,
        followers,
      }),
    })

    if (!claimResponse.ok) {
      const reason = await claimResponse.text()
      const alreadyClaimed = profile.data.username
        ? reason.includes('UNIQUE')
        : false

      return c.json(
        {
          message: 'Failed to create minting entry',
          error: alreadyClaimed
            ? `@${profile.data.username} already has a minting entry`
            : reason,
        },
        502,
      )
    }

    const result = await claimResponse.json().catch(() => ({ success: true }))

    return c.json(result)
  } catch (error) {
    console.error('Failed to process mint request', error)
    return c.json({ message: 'Failed to process mint request' }, 500)
  }
})

export default app
