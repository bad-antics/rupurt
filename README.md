<div align="center">

# 🔍 RKHunt v2.5

### Advanced Rootkit Hunter

<p>
  <img src="https://img.shields.io/badge/version-2.5.0-00ff00?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/signatures-200%2B-ff0000?style=for-the-badge" alt="Signatures">
  <img src="https://img.shields.io/badge/modules-13-blue?style=for-the-badge" alt="Modules">
  <img src="https://img.shields.io/badge/license-MIT-purple?style=for-the-badge" alt="License">
</p>

<p>
  <a href="https://github.com/bad-antics/nullsec-rkhunt"><img src="https://img.shields.io/github/stars/bad-antics/nullsec-rkhunt?style=social" alt="Stars"></a>
  <a href="https://github.com/bad-antics"><img src="https://img.shields.io/badge/NullSec-Toolkit-000000?style=flat-square&logo=github" alt="NullSec"></a>
</p>

*Comprehensive Linux rootkit detection with modern threat signatures, eBPF analysis, and APT implant detection*

</div>

---

## 💻 Tech Stack

### Core
![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![POSIX](https://img.shields.io/badge/POSIX-000000?style=for-the-badge&logo=gnu&logoColor=white)

### Detection Targets
![eBPF](https://img.shields.io/badge/eBPF-FF6600?style=for-the-badge&logo=linux&logoColor=white)
![Kernel](https://img.shields.io/badge/Kernel-326CE5?style=for-the-badge&logo=linux&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Kubernetes](https://img.shields.io/badge/K8s-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)

### Platforms
![AMD64](https://img.shields.io/badge/AMD64-ED1C24?style=for-the-badge&logo=amd&logoColor=white)
![ARM64](https://img.shields.io/badge/ARM64-0091BD?style=for-the-badge&logo=arm&logoColor=white)
![Raspberry Pi](https://img.shields.io/badge/RPi-A22846?style=for-the-badge&logo=raspberrypi&logoColor=white)

---

## 🎯 Features

<table>
<tr>
<td width="50%" valign="top">

### 🔬 Detection Modules (13)

| Module | Flag | Description |
|--------|:----:|-------------|
| **Process Analysis** | `-p` | Hidden processes via /proc vs kill() |
| **Library Injection** | auto | LD_PRELOAD, ld.so.preload hooks |
| **Kernel Modules** | `-m` | LKM rootkits, tainted kernel |
| **Filesystem** | `-f` | Rootkit files, SUID in temp |
| **Network** | `-n` | Backdoor ports, raw sockets |
| **Syscall Integrity** | `-s` | Kallsyms, kprobes, ftrace |
| **eBPF Analysis** | `-E` | BPF programs, suspicious mounts |
| **Boot Integrity** | `-b` | UEFI, initramfs, GRUB |
| **Container Security** | `-c` | Docker/K8s escapes |
| **Persistence** | `-e` | Cron, systemd, SSH keys |
| **File Integrity** | `-I` | ELF validation, ownership |
| **Memory Analysis** | `-M` | RWX regions, injections |

</td>
<td width="50%" valign="top">

### 🦠 Signature Database (200+)

| Category | Count | Examples |
|----------|:-----:|----------|
| **LKM Rootkits** | 70+ | singularity, reptile, diamorphine, kovid |
| **APT Implants** | 20+ | turla, equation, regin, drovorub |
| **eBPF Threats** | 15+ | ebpfkit, bpfdoor, pamspy, boopkit |
| **Userland** | 35+ | jynx2, azazel, vlany, beurk |
| **Bootkits** | 35+ | blacklotus, moonbounce, cosmicstrand |
| **Container** | 25+ | kinsing, doki, siloscape, teamtnt |

</td>
</tr>
</table>

---

## 📦 Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-rkhunt
cd nullsec-rkhunt

# Compile
gcc -O2 -Wall -o rkhunt src/rkhunt.c -lpthread

# Install (optional)
sudo cp rkhunt /usr/local/bin/
```

---

## 🚀 Usage

```bash
# Full comprehensive scan
sudo ./rkhunt -a

# Quick scan (processes, modules, preload)
sudo ./rkhunt -q

# Targeted modules
sudo ./rkhunt -m -s -E      # Modules + Syscalls + eBPF
sudo ./rkhunt -e -I -M      # Persistence + Integrity + Memory

# Output options
sudo ./rkhunt -a -v              # Verbose
sudo ./rkhunt -a -Q              # Quiet (alerts only)
sudo ./rkhunt -a -j              # JSON output
sudo ./rkhunt -a -l scan.log     # Log to file
sudo ./rkhunt -a -d              # Deep scan mode
```

### Command Reference

<details>
<summary>Click to expand all options</summary>

```
Scan Options:
  -a, --all           Full comprehensive scan (default)
  -q, --quick         Quick scan (processes, modules, preload)
  -p, --processes     Scan for hidden processes
  -m, --modules       Scan kernel modules
  -f, --files         Scan for rootkit files
  -n, --network       Check network backdoors
  -s, --syscalls      Check syscall table integrity
  -b, --boot          Check boot/UEFI integrity
  -c, --container     Container security checks
  -e, --persistence   Check persistence mechanisms
  -E, --ebpf          eBPF program analysis
  -I, --integrity     File integrity verification
  -M, --memory        Deep memory signature scan

Output Options:
  -v, --verbose       Verbose output
  -Q, --quiet         Minimal output (alerts only)
  -l, --log <file>    Log findings to file
  -j, --json          JSON output format
  -d, --deep          Enable deep scanning (slower)
```

</details>

---

## 📊 Severity Levels

| Level | Icon | Exit Code | Description |
|-------|:----:|:---------:|-------------|
| **CRITICAL** | █ | 2 | Active rootkit/compromise detected |
| **HIGH** | ▸ | 1 | Strong indicators of compromise |
| **MEDIUM** | ▹ | 0 | Suspicious activity, needs review |
| **LOW** | · | 0 | Minor anomalies, informational |

---

## 🖥️ Sample Output

```
  ╭──────────────────────────────────────────╮
  │  RKHunt v2.5  │  Advanced Rootkit Hunter  │
  │     github.com/bad-antics/nullsec-rkhunt │
  ╰──────────────────────────────────────────╯
  ▸ System: Linux 6.x.x x86_64
  ▸ Starting rootkit scan...

  ───── Kernel Modules ─────
   [ROOTKIT_LKM] █: Known rootkit module loaded: reptile

  ───── Persistence Mechanisms ─────
   [CRON] █: Reverse shell pattern in cron: /etc/cron.d/update

  ╭────────────────────────────────────────╮
  │           SCAN RESULTS                │
  ├────────────────────────────────────────┤
  │  Critical:             2                │
  │  High:                 0                │
  │  Medium:               1                │
  │  Low:                  0                │
  ╰────────────────────────────────────────╯

  █████ SYSTEM COMPROMISED █████
  2 critical finding(s) detected
  Immediate incident response recommended
```

---

## 🛡️ Part of NullSec Toolkit

<table>
<tr>
<td width="33%" valign="top">

### Core Security
- [nullsec-linux](https://github.com/bad-antics/nullsec-linux) — Full distro
- [nullsec-tools](https://github.com/bad-antics/nullsec-tools) — 135+ tools
- [nullsec-rkhunt](https://github.com/bad-antics/nullsec-rkhunt) — Rootkit hunter

</td>
<td width="33%" valign="top">

### Cloud & Container
- [nullsec-cloudaudit](https://github.com/bad-antics/nullsec-cloudaudit) — Multi-cloud
- [nullsec-k8sscan](https://github.com/bad-antics/nullsec-k8sscan) — Kubernetes
- [nullsec-terraform-scan](https://github.com/bad-antics/nullsec-terraform-scan) — IaC

</td>
<td width="33%" valign="top">

### Mobile & Hardware
- [nullkia](https://github.com/bad-antics/nullkia) — Mobile security
- [nullsec-canbus](https://github.com/bad-antics/nullsec-canbus) — CAN bus
- [nullsec-sdr](https://github.com/bad-antics/nullsec-sdr) — SDR analysis

</td>
</tr>
</table>

---

## 📝 Changelog

### v2.5.0 (2026-01-26)
- ✨ eBPF/BPF program analysis module
- ✨ File integrity verification module
- ✨ Severity-based reporting (Critical/High/Medium/Low)
- ✨ Deep scan mode
- 🦠 50+ new signatures (eBPF rootkits, APT implants)
- 🎨 Improved output formatting

### v2.0.0
- Complete rewrite with modular architecture
- 150+ rootkit signatures
- Container security checks

---

## 🔗 Connect

<div align="center">

[![Website](https://img.shields.io/badge/bad--antics.github.io-000000?style=for-the-badge&logo=github&logoColor=white)](https://bad-antics.github.io/)
[![Twitter](https://img.shields.io/badge/@AnonAntics-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/AnonAntics)
[![Discord](https://img.shields.io/badge/Discord-killers-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/killers)

</div>

---

<div align="center">

*For authorized security testing and research only.*

**© 2024-2026 bad-antics • NullSec Security Engineering**

</div>
