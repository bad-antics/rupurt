<div align="center">

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗                           ║
║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗                          ║
║   ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝                          ║
║   ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗                          ║
║   ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║                          ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝    v2.5                 ║
║                                                                              ║
║                    ☠️  Advanced Linux Rootkit Hunter ☠️                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

<p>
  <img src="https://img.shields.io/badge/n01d-reaper-ff0000?style=for-the-badge&logo=target&logoColor=white" alt="n01d">
  <img src="https://img.shields.io/badge/version-2.5.0-00ff00?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/signatures-250%2B-ff0000?style=for-the-badge" alt="Signatures">
  <img src="https://img.shields.io/badge/modules-15-blue?style=for-the-badge" alt="Modules">
  <img src="https://img.shields.io/badge/license-MIT-purple?style=for-the-badge" alt="License">
</p>

<p>
  <a href="https://github.com/bad-antics/n01d-reaper"><img src="https://img.shields.io/github/stars/bad-antics/n01d-reaper?style=social" alt="Stars"></a>
  <a href="https://github.com/bad-antics"><img src="https://img.shields.io/badge/n01d-toolkit-000000?style=flat-square&logo=github" alt="n01d"></a>
</p>

*Comprehensive Linux rootkit detection with modern threat signatures, eBPF analysis, memory forensics, and APT implant detection*

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

---

## ⚡ Features

### 🔍 Detection Modules

| Module | Description |
|--------|-------------|
| **Syscall Analysis** | Detects syscall table hijacking and hooking |
| **eBPF Scanner** | Identifies malicious eBPF programs |
| **Memory Forensics** | Scans for hidden processes and injected code |
| **Kernel Integrity** | Validates kernel text and module signatures |
| **Network Analysis** | Detects hidden network connections |
| **File System** | Finds hidden files and rootkit artifacts |
| **Process Scanner** | Identifies process hollowing and hiding |
| **Container Escape** | Detects container breakout attempts |
| **APT Detection** | Signatures for nation-state implants |

### 📊 Signature Database

- **250+ rootkit signatures** (Diamorphine, Reptile, Drovorub, etc.)
- **APT implant detection** (Equation Group, Turla, Lazarus)
- **Cryptominer detection** (XMRig, TeamTNT variants)
- **Container-specific threats** (Siloscape, cr8escape)

---

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/bad-antics/n01d-reaper
cd n01d-reaper

# Build from source
make

# Install system-wide
sudo make install

# Run scan
sudo reaper --full
```

## 📖 Usage

```bash
# Quick scan (essential checks)
sudo reaper --quick

# Full system scan
sudo reaper --full

# Paranoid mode (everything)
sudo reaper --paranoid

# Specific modules
sudo reaper --syscall --ebpf --memory

# JSON output for SIEM integration
sudo reaper --full --json > report.json

# Continuous monitoring
sudo reaper --monitor --interval 300
```

## 🔧 Command Line Options

| Option | Description |
|--------|-------------|
| `--quick` | Fast essential checks |
| `--full` | Complete system scan |
| `--paranoid` | Maximum detection sensitivity |
| `--syscall` | Syscall table analysis |
| `--ebpf` | eBPF program scanner |
| `--memory` | Memory forensics |
| `--kernel` | Kernel integrity check |
| `--network` | Hidden network detection |
| `--process` | Process hiding detection |
| `--container` | Container escape detection |
| `--apt` | APT implant signatures |
| `--json` | JSON output format |
| `--monitor` | Continuous monitoring mode |
| `--update` | Update signature database |

---

## 🎯 What It Detects

### Kernel Rootkits
- Syscall table modifications
- IDT/GDT hooks
- Kernel text modifications
- Hidden kernel modules
- Malicious eBPF programs

### Userspace Threats
- LD_PRELOAD hijacking
- Process injection
- Shared library hooking
- Hidden processes
- Memory-resident malware

### Container Threats
- Container escape attempts
- Privileged container abuse
- cgroup manipulation
- Namespace breakouts

### APT Implants
- Equation Group tools
- Turla Snake/Uroburos
- Lazarus Group malware
- Winnti backdoors

---

## 📁 Output Example

```
╔══════════════════════════════════════════════════════════════════╗
║                    n01d Reaper v2.5.0                           ║
║                  Advanced Rootkit Hunter                         ║
╚══════════════════════════════════════════════════════════════════╝

[*] Starting full system scan...
[+] Kernel: Linux 6.5.0-generic x86_64
[+] Scanning syscall table...
[+] Checking eBPF programs...
[!] WARNING: Suspicious eBPF program detected
    Program ID: 42
    Type: tracepoint
    Attach: sys_enter_openat
[+] Memory analysis...
[+] Checking hidden processes...
[+] Network connection analysis...
[+] File system scan...

══════════════════════════════════════════════════════════════════
                         SCAN SUMMARY
══════════════════════════════════════════════════════════════════
  Modules scanned: 15
  Checks performed: 847
  Warnings: 1
  Critical: 0
  Time elapsed: 12.4s
══════════════════════════════════════════════════════════════════
```

---

## 🔗 Part of the n01d Toolkit

| Tool | Description |
|------|-------------|
| [n01d-forge](https://github.com/bad-antics/n01d-forge) | Forensic disk imaging |
| [n01d-machine](https://github.com/bad-antics/n01d-machine) | Secure VM manager |
| [n01d-reaper](https://github.com/bad-antics/n01d-reaper) | Rootkit hunter |
| [n01d-media](https://github.com/bad-antics/n01d-media) | Cyberpunk media suite |
| [n01d-term](https://github.com/bad-antics/n01d-term) | Hacker terminal |
| [n01d-notes](https://github.com/bad-antics/n01d-notes) | Secure note-taking |

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">
  <p>
    <a href="https://github.com/bad-antics">
      <img src="https://img.shields.io/badge/Made%20with-☠️-ff0000?style=for-the-badge" alt="Made with skull">
    </a>
  </p>
  <p><i>Hunt the hunters. Reap the reapers.</i></p>
</div>
