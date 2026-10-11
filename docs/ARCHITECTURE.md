# Architecture

Npcap → BPF `ip and tcp` → Ethernet/IPv4/TCP parser → per-source heuristic tracker → Win32 alert log.

The parser reads captured Ethernet frames, checks IPv4 and TCP header lengths, and inspects SYN flags and certain cleartext HTTP request prefixes. The capture thread posts log messages to the GUI thread.

## Known engineering gaps

The tracking table has 128 hash slots and can evict colliding sources. Port and SYN thresholds share an alert cooldown, which can suppress one signal after another. Packet timestamps determine ten-second windows. HTTP matching is segment-local and cannot infer authentication success or failure. No TCP reassembly, IPv6, VLAN parsing, or durable audit log is implemented.
