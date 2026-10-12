# MovementHound: You might be missing something, move it!

- **Speaker(s):** Umberto Micillo (polair)
- **Event:** RomHack Camp 2026 (2026-10-02, Talk)

## Abstract

"You need local admin for that." It's one of the most repeated assumptions in offensive Windows tradecraft, and it's mostly wrong.

Most of these techniques are gated by a specific set of access-mask and DACL permissions, not by group membership, so the real question isn't "am I admin?" but "what do I actually need?" This talk answers that systematically: what each lateral-movement technique truly requires, instead of what folklore and our tooling assume.

We'll walk through the true minimum rights behind service creation and reconfiguration, DCOM, WinRM, WMI (over both DCOM and WSMAN), Remote Registry, Remote GhostTask, Remote Network Provider hijack, RDP and RDP Shadowing, SSH, and User Right Assignments. Along the way we'll hit the under-documented Microsoft policy that silently breaks "non-admin service creation," the granular access masks that make these paths work (0x0003 on the SCM, 0x00011 for shadowing, and friends), and why those same minimal rights double as quiet persistence.

The uncomfortable part cuts both ways. BloodHound edges, NetExec's "Pwned!", and group-membership checks systematically miss these configurations, so attackers slip through and defenders never see it. I'll cover MovementHound, a PowerShell minimal-rights enumerator that surfaces these overlooked paths and feeds the missing edges straight into BloodHound, with a recorded demo of it in action.

Expect granular access-mask details and honest caveats.

## Materials

- [Slides (PDF)](slides.pdf)
