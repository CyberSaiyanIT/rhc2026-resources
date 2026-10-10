# Stupid Sexy Bearer Tokens: a deep dive into exploding OIDC sessions and hardening with DPoP

- **Speaker(s):** jiraky, reymerk, Giuseppe, toctou, Stefano Maistri
- **Event:** RomHack Camp 2026 (2026-10-02, Talk)

## Abstract

Standard OIDC bearer tokens are deceptively simple and highly attractive to developers, but they hide a structurally weak security posture: anyone who holds them can spend them. Following up on [our previous deep dive](https://www.youtube.com/watch?v=ehSkbR-YuZw) @MOCA24 into securing OIDC code exchanges, this presentation is a hands-on, exploit-driven exploration of token-usage security.
We will begin by demonstrating how easily standard bearer tokens are stolen and replayed remotely from an attacker's terminal. We will then look "beyond the basics" to live-demo a hardened implementation of [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) (DPoP) using a Keycloak identity provider and an Express.js resource server.

## Materials

- [Slides (PDF)](slides.pdf)
- [Slides (Google Slides, public link from the speakers)](https://docs.google.com/presentation/d/12uTgYZX9nMiUWoKKB_72h66-PlRfgFa79rV8N-yzzWc/edit?usp=sharing)
