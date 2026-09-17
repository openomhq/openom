// Functional Supabase auth smoke (see .github/workflows/staging.smoke.yml).
//
// Availability alone (fetching the JWKS) proves nothing about auth working. So this does
// the real loop:
//   1. ISSUANCE  — sign the test user in via the password grant. A 200 with an
//      access_token proves the Supabase issuer actually mints tokens for a real user.
//   2. VERIFY    — validate that token against the project's published JWKS plus the
//      expected issuer/audience. This proves the JWKS we configured genuinely verifies
//      the tokens this project issues (catches a key/URL/claim mismatch).
//
// Node 20+ (global fetch). `jose` is installed from scripts/smoke/package.json by the
// workflow. This mirrors what the Rust server's verifier will assert in prod.

import { createRemoteJWKSet, jwtVerify } from 'jose'

const {
  SUPABASE_JWT_ISS: iss,
  SUPABASE_JWT_AUD: aud,
  SUPABASE_JWKS_URL: jwksUrl,
  SUPABASE_PUBLISHABLE_KEY: anon,
  SUPABASE_TEST_EMAIL: email,
  SUPABASE_TEST_PASSWORD: password,
} = process.env

for (const [k, v] of Object.entries({ iss, aud, jwksUrl, anon, email, password })) {
  if (!v) throw new Error(`missing env: ${k}`)
}

// 1. issuance — password grant against the auth endpoint
const res = await fetch(`${iss}/token?grant_type=password`, {
  method: 'POST',
  headers: { apikey: anon, 'content-type': 'application/json' },
  body: JSON.stringify({ email, password }),
})
if (!res.ok) {
  throw new Error(`Supabase sign-in failed: ${res.status} ${await res.text()}`)
}
const { access_token: token } = await res.json()
if (!token) throw new Error('sign-in succeeded but returned no access_token')

// 2. verification — must validate against the published JWKS + expected claims
const JWKS = createRemoteJWKSet(new URL(jwksUrl))
const { payload } = await jwtVerify(token, JWKS, {
  issuer: iss,
  audience: aud,
  algorithms: ['ES256'], // pin the alg (defense-in-depth vs algorithm confusion)
})
if (!payload.sub) throw new Error('verified token has no sub claim')

console.log(`Supabase OK — issued + JWKS-verified a token (sub=${payload.sub})`)
