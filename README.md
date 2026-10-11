 AegisWire NIDS — v1.1 (Experimental)

[![Windows Build](https://github.com/PedroGoncalves28286/AegisWire-NIDS-v1.1/actions/workflows/windows-build.yml/badge.svg)](https://github.com/PedroGoncalves28286/AegisWire-NIDS-v1.1/actions/workflows/windows-build.yml)
![Language](https://img.shields.io/badge/language-C17-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6)
![Status](https://img.shields.io/badge/status-experimental-orange)

**AegisWire** is a compact, educational **Network Intrusion Detection System (NIDS)** written in **C17** for **Windows 10/11**. It uses **Npcap** to capture packets, inspects Ethernet/IPv4/TCP traffic, and displays heuristic alerts in a native **Win32 GUI**.

> **Project status — experimental.** A Windows x64 build completed successfully in GitHub Actions, and a downloadable executable artifact was produced (as shown in the project's CI run). **Runtime behavior, packet capture, alert accuracy, and stability have not yet been validated on a Windows 11 test machine.** Do not deploy AegisWire as a production security control.

## Design philosophy

AegisWire follows a **minimalist, transparent, local-first** approach: learn the OSI model through direct packet parsing in C, keep detection logic understandable, and avoid mandatory cloud services or opaque machine-learning models. The aim is an approachable educational sensor, **not** a replacement for Snort or Suricata.

## Features and current status

| Feature | Implementation status | Notes |
| --- | --- | --- |
| Live capture via Npcap | Implemented; runtime testing pending | BPF filter: `ip and tcp` |
| Ethernet II / IPv4 / TCP parsing | Implemented; runtime testing pending | Basic packet-length checks |
| Single IEEE 802.1Q VLAN tag | Initial support; runtime testing pending | Stacked VLAN tags are not supported |
| TCP SYN port-scan indicator | Heuristic | 12 distinct destination ports in a 10-second tracking window |
| TCP SYN burst indicator | Heuristic | 150 SYN packets per tracking window |
| Cleartext HTTP login-request burst | Heuristic | Looks for `POST /login` or `POST /signin` in individual TCP segments, generally on ports 80/8080 |
| Native Win32 GUI | Implemented; runtime testing pending | Adapter selection, START, STOP, CLEAR LOG |
| Asynchronous STOP | Improved in v1.1 | Capture thread completion is signaled through a Windows message |
| Windows x64 CI build | **Passed** | GitHub Actions completed compilation and uploaded one executable artifact |

**Alerts are indicators, not evidence of compromise.** The application cannot read encrypted HTTPS payloads through ordinary packet capture. A matching HTTP request does not establish that authentication failed.

## Build verification versus runtime verification

The GitHub Actions **Windows Build** workflow has successfully run on a Windows x64 runner, including Npcap SDK download, CMake configuration, compilation, executable verification, and artifact upload. This confirms **build-time integration**, not that the program has been tested as a working IDS.

| Verification | Status |
| --- | --- |
| Windows x64 CI compilation | **Passed** |
| CMake configuration | **Passed** |
| Npcap SDK available to compiler/linker | **Passed (build time)** |
| `AegisWire.exe` produced | **Passed** |
| Executable uploaded as CI artifact | **Passed** |
| Launch and GUI interaction on Windows 11 | **Not yet verified** |
| Live Npcap capture | **Not yet verified** |
| SYN-scan / SYN-burst / HTTP detection | **Not yet verified** |
| Performance, false positives, memory safety | **Not yet verified** |

The workflow may display a **non-blocking deprecation warning** about Node.js 20 for older GitHub Actions dependencies. This is a CI maintenance issue, not evidence of a C compiler error; update action versions after checking their compatibility.

## Requirements

- Windows 10 or Windows 11 (x64 recommended).
- [Npcap runtime](https://npcap.com/#download) installed on the machine that will capture traffic.
- [Npcap SDK](https://npcap.com/#download) for building from source.
- Visual Studio 2022 Build Tools with **Desktop development with C++** and Windows SDK.
- [CMake](https://cmake.org/download/) 3.20 or later.
- Appropriate permissions for packet capture; administrator rights may be required depending on Npcap installation settings.

## Option A — Download the CI build artifact

1. Open [GitHub Actions](https://github.com/PedroGoncalves28286/AegisWire-NIDS-v1.1/actions/workflows/windows-build.yml).
2. Open a successful **Windows Build** run.
3. Under **Artifacts**, download **`AegisWire-NIDS-v1.1-Windows-x64`** (while the artifact is retained).
4. Extract the downloaded ZIP to a local directory and locate `AegisWire.exe`.
5. Install the **Npcap runtime** on the target Windows machine before attempting capture.

**Note:** CI artifacts are experimental build outputs, not tested installers or production releases. The artifact may expire according to the workflow retention policy.

## Option B — Build from source

### 1. Install and verify prerequisites

Install the Npcap runtime, extract the Npcap SDK (for example to `C:\Npcap-SDK`), and install Visual Studio 2022 Build Tools with the Windows SDK and CMake.

In a **Visual Studio Developer PowerShell**, verify:

```powershell
cmake --version
cl
Test-Path 'C:\Npcap-SDK\Include\pcap.h'
Test-Path 'C:\Npcap-SDK\Lib\x64\wpcap.lib'
Test-Path 'C:\Npcap-SDK\Lib\x64\Packet.lib'
```

The three `Test-Path` commands should return `True` when the SDK is extracted to that location. SDK layouts may vary; adapt paths as needed.

### 2. Get the source

```powershell
git clone https://github.com/PedroGoncalves28286/AegisWire-NIDS-v1.1.git
cd AegisWire-NIDS-v1.1
```

Alternatively, use **Code → Download ZIP** and open a terminal in the extracted repository root.

### 3. Configure and compile

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DNPCAP_SDK="C:/Npcap-SDK"
cmake --build build --config Release
```

Expected executable:

```text
build/Release/AegisWire.exe
```

If your SDK is elsewhere, change the value of `NPCAP_SDK`. The source build was demonstrated in CI; local Windows installations can still expose environment-specific issues.

## Running AegisWire

1. Ensure the **Npcap runtime** is installed.
2. Launch `AegisWire.exe` with the permissions required by your Npcap configuration.
3. Select a supported Ethernet-compatible capture adapter.
4. Click **START** and inspect packet counters and alerts.
5. Click **STOP** to request capture shutdown; use **CLEAR LOG** to clear the visible log.

Packet visibility depends on the chosen interface and network topology. A host cannot automatically see all traffic on a switched network. **Capture only on networks you own or are explicitly authorized to monitor.**

## Detection model

### TCP SYN port scanning

Tracks distinct destination TCP ports contacted by a source within a time window. The current threshold is **12 distinct ports in 10 seconds**. It is a heuristic and may generate false positives.

### TCP SYN bursts

Counts SYN packets from a source in a tracking window; the current threshold is **150 SYN packets**. This is **not** a validated SYN-flood classification and has no traffic baseline.

### Cleartext HTTP authentication activity

Checks individual visible TCP payloads for request prefixes such as `POST /login` and `POST /signin`, generally on ports 80/8080. It does **not** reassemble TCP streams, inspect HTTPS plaintext, or determine login success or failure.

## Known limitations

- Detection thresholds are hard-coded; there is no user-editable rule engine.
- The fixed-size tracking table can suffer collisions and state resets.
- Only limited Ethernet/IPv4/TCP parsing; no IPv6, UDP, ICMP, or ARP detection.
- Initial single-tag 802.1Q support; no stacked VLAN tags.
- No TCP stream reassembly, persistent event storage, or structured JSON export.
- No automated parser/detection unit tests or offline PCAP replay yet.
- No published throughput, packet-loss, memory-safety, or false-positive benchmarks.
- Build success does not prove runtime reliability or detection accuracy.

## Manual validation plan

Perform these checks **only in a controlled, authorized lab**:

1. Launch the application and verify that adapter selection and GUI controls respond.
2. Start capture on a suitable interface and verify packet counters against normal, known traffic.
3. Stop and restart capture repeatedly; check for freezes, resource leaks, or crashes.
4. Exercise the documented heuristics with controlled test traffic and compare the results with an independent packet capture.
5. Record false positives and negatives, especially for TCP segmentation and VLAN traffic.
6. Test truncated and malformed packet inputs once offline PCAP replay/test harness support exists.

See [docs/TESTING.md](docs/TESTING.md) and [docs/REVIEW.md](docs/REVIEW.md). **No runtime test results are claimed here.**

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `pcap.h` not found | `NPCAP_SDK` path and `Include/pcap.h` |
| `wpcap.lib` / `Packet.lib` not found | SDK library directory and x64 architecture |
| `cl` is not recognized | Open Visual Studio Developer PowerShell and install the C++ toolchain |
| No capture adapters | Npcap runtime installation, privileges, adapter compatibility |
| No packets | Selected interface, BPF filter, traffic visibility, network topology |
| No alerts | Thresholds, traffic patterns, ports, visibility, TCP segmentation |
| GUI does not respond | Capture thread lifecycle; collect steps to reproduce and Windows logs |
| CI warning about Node.js | GitHub Actions dependency version compatibility; not a C build failure |

When reporting a problem, include the operating system, Npcap version, compiler version, full error output, and reproducible steps. Avoid sharing private network captures or credentials.

## Repository layout

```text
AegisWire-NIDS-v1.1/
├── .github/
│   └── workflows/
│       └── windows-build.yml
├── docs/
│   ├── ARCHITECTURE.md
│   ├── REVIEW.md
│   └── TESTING.md
├── src/
│   └── main.c
├── CMakeLists.txt
├── CONTRIBUTING.md
├── LICENSE
├── README.md
└── SECURITY.md
```

A `.gitignore` is recommended for local build artifacts if it is not already present in the repository.

## Roadmap

- [x] Compile the Windows x64 project in GitHub Actions.
- [x] Verify and upload the CI executable artifact.
- [ ] Validate launch, capture, STOP behavior, and alerts on Windows 11.
- [ ] Add parser unit tests and offline PCAP replay.
- [ ] Separate capture, parsing, detection, and GUI into modules.
- [ ] Replace collision-prone tracking with collision-safe state.
- [ ] Add configurable thresholds and structured JSON alert logging.
- [ ] Extend protocol coverage (IPv6, UDP, ICMP, ARP).
- [ ] Integrate alerts with Wazuh or another SIEM.
- [ ] Benchmark throughput, packet loss, and false-positive rates.
- [ ] Refresh GitHub Actions dependencies and document compatibility.

## Project evolution

This repository preserves **v1.1** as an incremental stability-focused evolution of the [original AegisWire NIDS v1.0](https://github.com/PedroGoncalves28286/AegisWire-NIDS).

Version 1.1 introduces improvements to capture shutdown, independent detection cooldowns, initial 802.1Q VLAN handling, expanded tracking capacity, build diagnostics, and Windows CI automation. Both versions are retained for educational comparison.

## Responsible use and security

AegisWire is intended for **defensive education and authorized network monitoring**. It is not an enterprise-ready IDS and should not be relied upon as the sole security control. See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.
## Windows Build Support

AegisWire NIDS v1.1.1 supports two Windows build toolchains.

| Toolchain | Build Status | Runtime Status |
|-----------|--------------|----------------|
| MSVC / Visual Studio 2022 | Verified | Partially tested |
| GCC 16.2.0 / MSYS2 UCRT64 | Verified | Blocked by Windows Smart App Control |

### GCC / MSYS2 Build

Requirements:

- Windows 10/11 x64
- MSYS2 UCRT64
- GCC 16.2.0
- CMake 4.4.4
- MinGW-w64 Make
- Npcap SDK 1.16
- Npcap Runtime

Build commands:

```bash
cmake -S . -B build-gcc \
  -G "MinGW Makefiles" \
  -DCMAKE_BUILD_TYPE=Release \
  -DNPCAP_SDK="C:/path/to/Npcap-SDK"

cmake --build build-gcc
## Attribution

Inspired by the educational presentation *Minimalistic IDS (Intrusion Detection System) in C — Part 1* by **Licínio Ferreira**. AegisWire is a separate educational implementation; attribution does not imply endorsement or authorship by the presenter.

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE).
## Project Contributors & Acknowledgements

### Project Development

**AegisWire NIDS** is an open-source educational Network
Intrusion Detection System developed and maintained by
Pedro Gonçalves.

The project focuses on lightweight network traffic monitoring,
native C17 programming, transparent detection mechanisms,
and practical cybersecurity education.

### Invited Collaborator

**Licínio Ferreira** — Technical Contributor (Invitation Pending)

Licínio Ferreira has been invited to collaborate on the
AegisWire NIDS project through GitHub.

His educational presentation, *Minimalistic IDS
(Intrusion Detection System) in C — Part 1*, provided
technical inspiration for the project's initial development.

Licínio has also demonstrated and tested an experimental
version of AegisWire using GCC/MinGW, including packet
capture and TCP SYN port scan detection.

Potential areas of collaboration include:

- C17 development and code review.
- GCC/MinGW compatibility.
- Network packet analysis.
- Intrusion detection improvements.
- Functional testing and technical validation.

The collaboration invitation is currently pending acceptance.

### Acknowledgements

Special thanks to Licínio Ferreira for sharing his
knowledge and educational work on network intrusion
detection systems.

AegisWire NIDS remains an independently maintained
educational project.
