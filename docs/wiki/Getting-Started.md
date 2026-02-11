# Getting Started

## Prerequisites

| Package | Purpose | Install |
|---------|---------|---------|
| GCC/Clang | Compilation | `apt install build-essential` |
| Linux headers | Kernel module scanning | `apt install linux-headers-$(uname -r)` |
| libelf | ELF binary analysis | `apt install libelf-dev` |
| libbpf | eBPF support | `apt install libbpf-dev` |

## Build

```bash
git clone https://github.com/bad-antics/rupurt
cd rupurt
make
sudo make install  # Optional: install to /usr/local/bin
```

## First Scan

```bash
# Quick scan (most common rootkits)
sudo ./rupurt --quick

# Full comprehensive scan
sudo ./rupurt --full-scan

# Specific module only
sudo ./rupurt --module kernel-check

# Output to file
sudo ./rupurt --full-scan --output report.txt --format json
```

## Understanding Output

```
[✓] PASS  — No threat detected
[!] WARN  — Suspicious but not confirmed
[✗] FAIL  — Threat detected
[i] INFO  — Informational
```
