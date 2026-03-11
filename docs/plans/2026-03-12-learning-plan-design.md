# Learning Plan Design

## Goal
Personal reference learning journal for authn/authz concepts, structured as concept-first deep dives with quizzes and system design interview questions.

## Audience
Myself — built this project with AI help, want to deeply understand every piece.

## Structure

### README.md (root)
Concise hub: what this is, quick start, learning roadmap linking to docs, architecture overview, project structure.

### Deep-Dive Docs (docs/)
Each doc follows: Concept → How It Works → In This Codebase → Quiz → System Design Interview Questions.

1. `01-authentication-basics.md` — AuthN vs AuthZ, password hashing, sessions vs tokens, blocklisting
2. `02-jwt-deep-dive.md` — JWT structure, signing, access/refresh/ID tokens, expiry, JTI revocation
3. `03-oauth2-flows.md` — Delegated auth, authorization code flow, client credentials, PKCE
4. `04-openid-connect.md` — OIDC identity layer, ID tokens, userinfo, scopes, nonce
5. `05-rbac-and-authorization.md` — Roles vs permissions vs scopes, token claims, decorator enforcement
