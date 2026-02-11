# rupurt Wiki

Welcome to **rupurt** — a comprehensive Linux rootkit detection tool with 280+ signatures, eBPF analysis, memory forensics, and APT implant detection.

## Navigation

- [[Getting Started]] — Install and run your first scan
- [[Detection Modules]] — All 15 detection modules explained
- [[Signature Database]] — Understanding the 280+ signatures
- [[eBPF Analysis]] — Kernel-level behavioral monitoring
- [[Memory Forensics]] — RAM scanning for hidden threats
- [[Configuration]] — Tuning and customization
- [[Interpreting Results]] — Understanding scan output
- [[Contributing Signatures]] — Add new detection rules

## Quick Start

```bash
git clone https://github.com/bad-antics/rupurt
cd rupurt
make
sudo ./rupurt --full-scan
```
