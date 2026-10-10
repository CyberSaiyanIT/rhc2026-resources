# GNOME and Beyond Dream Tour: Discover Linux desktop sandboxing and more through its vulnerabilities

- **Speaker(s):** Edoardo Geraci
- **Event:** RomHack Camp 2026 (2026-10-03, Talk)

## Abstract

Unlike mobile environments, The Linux desktop paradigm wasn’t really designed with app-level security, permissions and sandboxing in mind. Despite this, modern desktop environments try to shoehorn this in with systems such as Flatpak and desktop portals.

We went digging into GNOME ecosystem security, investigating its core libraries (glib, libsoup, and gvfs) and sandboxing mechanisms (Flatpak, bubblewrap, dbus-proxy, and desktop portals). During this journey into the GNOME world we uncovered numerous security issues, resulting in more than 14 CVEs, including a full, zero-precondition Flatpak sandbox escape.

We’ll take you along our very same journey where you’ll discover how permissions and security boundaries are enforced and rely on a web of libraries and tools, some of which seemingly unaware of their importance in the overall chain. This way you’ll be able to see with your own eyes what issues arise in such a complex environment where a couple of small mistakes, or colliding opinions, can lead to impactful vulnerabilities. We’ll also take a few detours to show critical issues that we found in widely used open source productivity software, and how those vulnerabilities can have a severe impact also outside of the desktop paradigm.

## Materials

- [Slides (PDF)](slides.pdf)
