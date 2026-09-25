# Staging gate

## What it is — and is not

The Cloudflare Pages middleware in this directory keeps the pre-release staging web application behind
one shared password and displays deployment and backend-health information before admission. It is not
application authentication: Supabase and the durable account session remain responsible for user identity.

The form is a normal successful HTML representation (`200`), not an HTTP `401` authentication challenge.
Correct submission sets a secure, HTTP-only cookie and redirects to the app; incorrect submission renders
the form again with an error. Missing password configuration fails closed with `503`.

## Invariants

| ID | Contract | Verified by |
| --- | --- | --- |
| SG-1 | An unauthenticated browser receives a renderable, non-cacheable password form without access to the app. | `test/stagingGate.test.js` |
| SG-2 | Only the configured password issues the secure admission cookie and redirects to the app. | `test/stagingGate.test.js` |
