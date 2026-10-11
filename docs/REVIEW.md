# AegisWire NIDS — v1.1 stabilization review

This release retains the original educational philosophy: a compact, native C/Win32 Npcap sensor, with explainable heuristics and no external cloud dependencies.

## Changes from v1.0
- STOP now requests capture termination asynchronously; completion is handled through WM_DONE.
- Closing the window waits for worker termination using a short UI timer, without an indefinite blocking wait.
- Independent alert cooldown timestamps for SYN scan, SYN burst and HTTP login signals.
- Basic single-tag 802.1Q parsing.
- More tracker slots (512); hash collisions remain a limitation.
- MSVC warning level /W4.

## Important remaining limitations
- No Windows build or Npcap runtime validation has been performed.
- Single source file, fixed hash tracker with collisions, no TCP reassembly, no IPv6, no JSON export, no signature rules.
- The GUI remains an educational log viewer; large traffic volumes may overwhelm it.
- A packet matching `POST /login` does **not** prove authentication failure.
- Do not use as a production security control.

## Validation checklist
1. Build with MSVC and Npcap SDK.
2. Start and stop capture repeatedly, including window close while capture is active.
3. Confirm Ethernet and VLAN capture behavior.
4. Exercise SYN scanning and repeated cleartext HTTP POST requests in an authorized isolated lab.
5. Confirm that false positives, packet drops and GUI responsiveness are documented.
