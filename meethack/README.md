# Meethack at RomHack Camp 2026

- **Organization:** [Meethack](https://meethack.it) (hackerspace / cybersecurity community based in Torino)
- **Event:** RomHack Camp 2026 (2026-10-02/03, Workshop and CTFs at the Meethack stand)
- **Original resources page:** <https://meethack.it/resources/>

Meethack brought a CI/CD security workshop and two CTF challenges to the Camp.
These were not regular talks, but the material is worth keeping. This folder
collects the slides and links to the challenges.

## Workshop: Pwn the Pipeline: A Hands-On Tour of CI/CD Security Risks

- **Speaker(s):** m3ssap0, Mattia Brollo, Fleeenz, IadRabbit
- **Date:** 2026-10-02 (the remaining challenges were solved at the Meethack stand on 2026-10-03)

Modern software delivery runs on CI/CD pipelines and attackers know it. From the SolarWinds Orion backdoor to the Codecov Bash Uploader compromise and the countless exposed Jenkins instances found on Shodan, build systems have become one of the most valuable and least monitored targets in the software supply chain. A single misconfigured runner, an overprivileged token, or a poisoned dependency can silently compromise everything downstream; and the rise of AI-based attacking agents, capable of autonomously discovering and chaining misconfigurations at scale, is only raising the stakes.

This workshop is a practical introduction to CI/CD security through the lens of the OWASP Top 10 CI/CD Security Risks. We'll walk through each risk category (insufficient flow control, poisoned pipeline execution, dependency chain abuse, exposed secrets, insecure system configuration, and more) grounding each one in real-world incidents that made these risks tangible rather than theoretical.

After the theory, attendees get their hands dirty with a set of self-contained challenges built on the CICD Goat vulnerable-by-design environment, hunting for and exploiting common pipeline misconfigurations and attack chains, followed by a guided walkthrough of each solution.

Prerequisites: basic web/Linux exploitation knowledge, familiarity with git, and a laptop with Docker and a git client installed.

- [Slides (PDF)](pwn-the-pipeline-slides.pdf)
- [cicd-goat](https://github.com/meethack-torino/cicd-goat): companion repository, a deliberately vulnerable CI/CD environment (Apache-2.0)

## CTF: NFC (Mifare Classic 1K) "Cyber Car Wash"

NFC CTF based on the Mifare Classic 1K chip, run by IadRabbit at the Meethack
stand (2026-10-02, solutions revealed on 2026-10-03).

- [CyberCarWasher](https://github.com/IadRabbit/CyberCarWasher)
- [CyberCarWasherAdmin](https://github.com/IadRabbit/CyberCarWasherAdmin)
- Walkthrough by Matteo Cosentino (0xless), **contains spoilers**: [Meethack x RomHack Cyber Car Wash CTF](https://lessonsec.com/posts/meethack_x_romhack_car_wash_ctf_walkthrough/). Third-party content, linked and not mirrored here.

## CTF: JANUS (AI)

Offline bilingual AI security CTF for RomHack 2026 (local LLM, prompt injection, voice, scoring and kiosk mode).

- [JANUS_AI_CTF](https://github.com/Redragon948/JANUS_AI_CTF) (Apache-2.0)
