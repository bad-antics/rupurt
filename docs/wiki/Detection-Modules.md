# Detection Modules

## Module Overview

| # | Module | Detection Target |
|---|--------|-----------------|
| 1 | `kernel-check` | Modified kernel symbols |
| 2 | `syscall-table` | Hooked system calls |
| 3 | `hidden-files` | Hidden files/directories |
| 4 | `hidden-procs` | Hidden processes |
| 5 | `hidden-ports` | Hidden network ports |
| 6 | `module-check` | Malicious kernel modules |
| 7 | `memory-scan` | In-memory rootkit artifacts |
| 8 | `ebpf-monitor` | Malicious eBPF programs |
| 9 | `binary-check` | Modified system binaries |
| 10 | `log-check` | Tampered log files |
| 11 | `network-check` | Suspicious network connections |
| 12 | `persistence` | Boot/init persistence mechanisms |
| 13 | `container-check` | Container escape indicators |
| 14 | `apt-implants` | Known APT implant signatures |
| 15 | `integrity` | File integrity verification |

## Module Details

### 1. kernel-check
Compares running kernel symbol table against known-good values. Detects function pointer hooking in the kernel.

### 2. syscall-table
Reads the system call table and verifies each entry points to a legitimate kernel function. Detects inline hooking and table modification.

### 3. hidden-files
Cross-references `readdir()` output with raw filesystem reads to find files hidden by rootkits modifying VFS layer.

### 4. ebpf-monitor
Enumerates all loaded eBPF programs and checks for:
- Programs attached to security-sensitive hooks
- Programs modifying return values
- Unauthorized tracepoint/kprobe attachments
