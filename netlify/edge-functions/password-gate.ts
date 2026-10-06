import type { Config, Context } from '@netlify/edge-functions'

const COOKIE_NAME = 'site_access'
const LOGIN_PATH = '/__site-login'
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30 // 30 days

async function sha256(value: string): Promise<string> {
  const data = new TextEncoder().encode(value)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

const TOKEN_SALT = 'seraph-site-access-v1'
const TOKEN_ITERATIONS = 60000

// One-way verifier for the built-in site password: sha256(accessToken(password)).
// Only the hash is stored so the password itself never appears in the code.
const DEFAULT_PASSWORD_VERIFIER = '1f9f62166dc36e9572886c68072f483af0efc8b108f8e43fe5ffce76dcacbc77'

// The access token is a slow PBKDF2 hash of the password. It is stored in the visitor's
// cookie, and each request is checked by hashing it once more and comparing to the verifier.
async function accessToken(password: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, [
    'deriveBits',
  ])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(TOKEN_SALT), iterations: TOKEN_ITERATIONS },
    key,
    256,
  )
  return Array.from(new Uint8Array(bits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

const verifierCache = new Map<string, Promise<string>>()

// SITE_PASSWORD, when set, overrides the built-in password. Changing it signs everyone out.
function passwordVerifier(): Promise<string> {
  const password = Netlify.env.get('SITE_PASSWORD')
  if (!password) return Promise.resolve(DEFAULT_PASSWORD_VERIFIER)
  let verifier = verifierCache.get(password)
  if (!verifier) {
    verifier = accessToken(password).then(sha256)
    verifierCache.set(password, verifier)
  }
  return verifier
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

function safeRedirectTarget(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.startsWith(LOGIN_PATH)) {
    return '/'
  }
  return value
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)
}

function loginPage(redirectTo: string, message = '', status = 401): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex">
  <title>Password required | Seraph</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: #0d0d12; color: #e8e8f0;
      font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    }
    form {
      width: min(360px, 90vw); padding: 32px; border-radius: 14px;
      background: #17171f; border: 1px solid #2a2a36; box-shadow: 0 20px 60px rgba(0,0,0,.5);
    }
    h1 { margin: 0 0 6px; font-size: 22px; }
    p { margin: 0 0 20px; color: #9a9aad; font-size: 14px; }
    input {
      width: 100%; padding: 12px 14px; border-radius: 8px; font-size: 15px;
      border: 1px solid #33334a; background: #0f0f16; color: inherit; outline: none;
    }
    input:focus { border-color: #7c6cff; }
    button {
      width: 100%; margin-top: 14px; padding: 12px; border: 0; border-radius: 8px;
      background: #7c6cff; color: #fff; font-size: 15px; font-weight: 600; cursor: pointer;
    }
    button:hover { background: #6a59f5; }
    .error { margin: 14px 0 0; color: #ff6b81; font-size: 14px; }
  </style>
</head>
<body>
  <form method="POST" action="${LOGIN_PATH}">
    <h1>Password required</h1>
    <p>Enter the password to continue to the site.</p>
    <input type="hidden" name="redirect" value="${escapeHtml(redirectTo)}">
    <input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required>
    <button type="submit">Enter</button>
    ${message ? `<p class="error">${escapeHtml(message)}</p>` : ''}
  </form>
</body>
</html>`
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  })
}

export default async (req: Request, context: Context) => {
  const url = new URL(req.url)
  const verifier = await passwordVerifier()

  if (url.pathname === LOGIN_PATH) {
    if (req.method !== 'POST') {
      return loginPage(safeRedirectTarget(url.searchParams.get('redirect')))
    }
    const form = await req.formData()
    const submitted = String(form.get('password') ?? '')
    const redirectTo = safeRedirectTarget(String(form.get('redirect') ?? '/'))

    const token = await accessToken(submitted)
    if (!timingSafeEqual(await sha256(token), verifier)) {
      return loginPage(redirectTo, 'Incorrect password. Please try again.')
    }

    context.cookies.set({
      name: COOKIE_NAME,
      value: token,
      path: '/',
      httpOnly: true,
      secure: url.protocol === 'https:',
      sameSite: 'Lax',
      maxAge: COOKIE_MAX_AGE,
    })
    return new Response(null, {
      status: 303,
      headers: { location: redirectTo, 'cache-control': 'no-store' },
    })
  }

  const cookie = context.cookies.get(COOKIE_NAME)
  if (cookie && timingSafeEqual(await sha256(cookie), verifier)) {
    return context.next()
  }

  return loginPage(url.pathname + url.search)
}

export const config: Config = {
  path: '/*',
}
