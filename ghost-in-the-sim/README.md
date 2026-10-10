# Ghost in the SIM: Silent, Zero-Click, Over-the-Air Exploitation of a Pixel 9 Baseband OOB Read

- **Speaker(s):** Lorenzo Valeriani, Pasquale Caporaso
- **Event:** RomHack Camp 2026 (2026-10-03, Lightning Talk)

## Abstract

Cellular baseband processors run highly privileged, proprietary software beneath the main OS, making them a critical yet hard-to-analyze attack surface. Focusing on the Google Pixel 9 modem, this talk demonstrates how adapting open-source emulation software allowed us to build a baseband fuzzing pipeline, surfacing three new vulnerabilities and several rediscoveries, including an Out-of-Bounds (OOB) read in 5G message parsing.
After validating the flaw with Software Defined Radios (SDRs), we address the challenge of turning local memory leaks into full remote attacks. We show how SIM Toolkit (STK) applets, legitimate applications running on SIMs/eSIMs that can be provisioned over-the-air, can be repurposed as a delivery and execution primitive operating entirely outside main OS visibility. Finally, we detail how pairing remote STK provisioning with the 5G baseband vulnerability creates a silent, zero-click exfiltration chain that leaks sensitive memory over SMS.

## Materials

- [Slides (PDF)](slides.pdf)
