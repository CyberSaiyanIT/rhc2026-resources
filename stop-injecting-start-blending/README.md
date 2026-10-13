# Stop Injecting, Start Blending: A KISS Approach to Malware Development

- **Speaker(s):** Julien Bedel
- **Event:** RomHack Camp 2026 (2026-10-02, Talk)

## Abstract

As EDR products continue to improve their ability to detect malicious behavior, malware developers are increasingly adding layers of complexity in an attempt to evade detection.

One of the most challenging operations to perform under the radar remains code injection. This seemingly unavoidable step is associated with numerous indicators of compromise, ranging from well-known Windows API calls to uncommon memory permissions or suspicious execution flows.

To address this challenge, we revisit the decade-old technique of *code caves*: unused memory locations within legitimate binaries that can be repurposed to host and execute malicious code. By extending the concept to include *dead code* and embracing position-independent payload development we show that it is not only possible to go beyond classic code cave limitations, but also eliminate the need for code injection altogether.

Through practical demonstrations, we will show how it is possible to automate the discovery and weaponization of dead code in legitimate binaries. This proof of concept advocates a renewed philosophy of malware development, emphasizing simplicity and minimalism rather than increasingly complex evasion chains.

Finally, we discuss important defensive implications of this work : if attackers can increasingly avoid traditional injection artifacts, detection strategies should focus less on how code reached execution and more on what that code ultimately does.

## Materials

- [Slides (PDF)](slides.pdf)
