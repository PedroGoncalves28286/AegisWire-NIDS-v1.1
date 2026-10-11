# Manual test plan (not yet executed)

1. Compile using the documented Windows + Npcap SDK environment. Record compiler, SDK, architecture and any warnings.
2. Start the GUI; verify interface list and START/STOP operation.
3. Capture authorized normal HTTP traffic; check packet counter increments.
4. In an isolated lab, generate a limited TCP SYN scan against a consenting test host; confirm alert behavior and false positives.
5. Send repeated **unencrypted** test requests to a local `/login` endpoint; confirm the alert is heuristic only.
6. Test malformed/truncated PCAP frames via future offline replay tests before production claims.
7. Verify stop/exit under idle and busy capture; inspect for hangs and memory leaks.

No test results are claimed in this repository.
