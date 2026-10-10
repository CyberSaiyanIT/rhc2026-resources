# Cash, Card or Root? Security Archaeology of a Fiscal Cash Register

- **Speaker(s):** Jacopo Jannone, Jacopo Moioli
- **Event:** RomHack Camp 2026 (2026-10-03, Talk)

## Abstract

Fiscal cash registers are everywhere in Italy, yet they receive surprisingly little attention as embedded systems. They are regulated appliances with tamper-evident seals, periodic inspections, controlled service procedures, and hardware mechanisms intended to make fiscal data difficult to manipulate.
We bought one of the most common models on the second-hand market and started taking it apart. Inside, we found an unusual design: an FPGA driving the user interface, an internal battery supporting a peculiar power lifecycle, a resin-encapsulated memory module, and physical switches hidden on the main board.

The software architecture is much more familiar: the device runs an old Linux-based OS with a writable root filesystem, essentially no privilege separation, extensive debug functionality, and a broad network attack surface.

Whether you prefer hardware or software, we found ways in from both sides. Rather than presenting a vulnerability catalogue, this talk examines the security model of a regulated embedded system and the mismatch between elaborate physical protections and weak software trust boundaries.
What does “tamper resistant” mean when the protected component is connected to a general-purpose computer with weak security assumptions?

By the end of the talk, we’ll have answered that question and one more: does it run Doom?

## Materials

- [Slides (PDF)](slides.pdf)
