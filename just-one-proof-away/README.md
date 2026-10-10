# Just one proof away: the cryptography behind private payments

- **Speaker(s):** Giorgio Dell'Immagine
- **Event:** RomHack Camp 2026 (2026-10-02, Talk)

## Abstract

Building private payments is a fascinating technical challenge. Somehow, we have to hide some combination of three things: who is paying, who is being paid, and how much. All without letting anyone print infinite money. This talk is about the cryptographic machinery and approaches people have come up with to make private payments possible and practical today. We focus on two projects, Monero and Zcash, which are among the most mature and influential systems.

In the talk we will start from a few simple cryptographic primitives: additively homomorphic commitments, ring signatures, stealth addresses, and zero-knowledge proofs. Then we dissect how transactions work in both Monero and Zcash, highlighting differences and similarities.

We close with a short, uncomfortable observation: when a system hides payments well, a forged proof is indistinguishable from an honest one, leaving us always just one proof away from trouble.

## Materials

- [Slides (PDF)](slides.pdf)
