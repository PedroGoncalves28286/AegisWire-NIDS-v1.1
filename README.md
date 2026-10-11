# AegisWire NIDS — v1.1 (experimental)

**AegisWire** is a small educational Network Intrusion Detection System written in **C17** for **Windows 10/11**. It captures packets with **Npcap**, parses Ethernet/IPv4/TCP traffic, detects selected traffic patterns, and displays alerts through a native **Win32 GUI**.

> **Status:** experimental, not compiled or runtime-validated in this delivery. Do not deploy as a production security control.

## Design philosophy

A compact, transparent, local-first network sensor: learn the OSI model through real C packet parsing, keep the detection rules understandable, and avoid cloud services and opaque machine-learning models.

## Capabilities

| Feature | Status | Notes |
|---|---|---|
| Npcap capture | Implemented, unverified | BPF `ip and tcp` |
| Ethernet II / IPv4 / TCP | Implemented, unverified | Basic bounds checks |
| Single 802.1Q VLAN tag | Implemented, unverified | Double-tagged frames unsupported |
| SYN port scan | Heuristic | 12 unique ports per 10-second window |
| SYN burst | Heuristic | 150 SYN packets per window |
| HTTP login request bursts | Heuristic | Cleartext TCP segments only; no stream reassembly |
| Native Win32 GUI | Implemented, unverified | Adapter selector, START/STOP/CLEAR LOG |
| Asynchronous STOP | Improved in v1.1 | Capture thread completion via Windows message |

Alerts are indicators, **not evidence of compromise**. HTTPS payloads are not visible to this packet sniffer.

## Requirements

- Windows 10 or Windows 11 (x64 recommended).
- [Npcap runtime](https://npcap.com/#download), installed with permissions to capture on the chosen interface.
- [Npcap SDK](https://npcap.com/#download), extracted to `C:\Npcap-SDK` (or another directory).
- Visual Studio 2022 with **Desktop development with C++** and Windows SDK.
- [CMake](https://cmake.org/download/) 3.20 or later.

## Step-by-step installation and build

1. Install the Npcap runtime from its official site.
2. Download the **SDK** separately and extract it to `C:\Npcap-SDK`. Confirm that `Include/pcap.h`, `Lib/x64/wpcap.lib` and `Lib/x64/Packet.lib` exist. SDK layouts vary: inspect your extracted directories.
3. Install Visual Studio Build Tools and the Windows SDK; open **x64 Native Tools Command Prompt for VS 2022** or the Visual Studio Developer PowerShell.
4. Clone this repository or download it as ZIP and extract it.
5. Run the following commands from the repository root:

```powershell
cmake --version
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DNPCAP_SDK="C:/Npcap-SDK"
cmake --build build --config Release
```

If compilation succeeds, the expected output is `build/Release/AegisWire.exe`. These commands have **not** been validated on Windows in this delivery.

## Running the application

1. Start the executable with appropriate capture permissions.
2. Choose an Ethernet-compatible capture adapter.
3. Press **START** and inspect packet and alert counters.
4. Press **STOP** to request a graceful capture shutdown.
5. Use **CLEAR LOG** to clear the visible event history.

Capture visibility depends on network topology and interface configuration. Only monitor networks you own or are authorized to assess.

## Detection model and limitations

- **SYN scan:** unique TCP destination ports per source within a tracking window.
- **SYN burst:** SYN packet volume per source; not a validated flood classification.
- **HTTP login burst:** matches `POST /login` or `POST /signin` at the start of an individual TCP segment on ports 80/8080. Does not infer authentication outcome.
- Detection thresholds are hard-coded.
- The tracker uses a fixed hash table, so collisions can reset state.
- No IPv6, UDP/ICMP/ARP detection, TCP stream reassembly, persistent logs, signature rules, or performance benchmarks.

## Troubleshooting

| Symptom | Suggested check |
|---|---|
| `pcap.h` missing | Check `NPCAP_SDK` and the SDK `Include` folder |
| `wpcap.lib` missing | Check `Lib/x64` and the selected build architecture |
| No adapters | Verify Npcap installation and capture permissions |
| No alerts | Check interface, BPF scope, thresholds and network visibility |
| Build error | Copy the complete compiler output and check Visual Studio components |

## Repository structure

```text
AegisWire-NIDS/
├── src/main.c
├── CMakeLists.txt
├── docs/ARCHITECTURE.md
├── docs/TESTING.md
├── docs/REVIEW.md
├── .github/workflows/windows-build.yml
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── .gitignore
```

## Verification status

A GitHub Actions Windows build workflow is included, but its successful execution has **not** been confirmed. See [testing plan](docs/TESTING.md) and [v1.1 review](docs/REVIEW.md). The Npcap SDK download URL used by the workflow must be verified before relying on CI.

## Roadmap

- [ ] Verify MSVC/Npcap compilation and GUI lifecycle.
- [ ] Add parser unit tests and offline PCAP replay.
- [ ] Modularize packet capture, parsing, detection and GUI.
- [ ] Replace hash tracker with collision-safe state.
- [ ] Add protocol coverage and configurable detection thresholds.
- [ ] Export structured JSON alerts for Wazuh/SIEM integration.
- [ ] Benchmark throughput, packet loss, and false positives.

## Attribution

Inspired by *Minimalistic IDS (Intrusion Detection System) in C — Part 1* by Licínio Ferreira. This is a separate educational implementation; attribution does not imply endorsement.

## License

MIT — see [LICENSE](LICENSE).
