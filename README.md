# 🔍 RKHunt - Advanced Rootkit Hunter

A comprehensive rootkit detection tool with an extensive signature database covering 150+ known rootkits, bootkits, and malware families.

## Features

- **Vast Rootkit Database** - 150+ signatures including:
  - Modern LKM rootkits (Singularity, Reptile, Diamorphine, Kovid, Suterusu)
  - Userland rootkits (Jynx2, Azazel, BEURK, Vlany, BDVl)
  - Bootkits & UEFI threats (BlackLotus, MoonBounce, CosmicStrand)
  - Container/Cloud malware (Doki, Kinsing, TeamTNT, Siloscape)
  - APT/Nation-state tools (Turla, Equation, Regin, Drovorub)

- **Detection Capabilities**
  - Hidden process detection via /proc enumeration
  - LD_PRELOAD hook analysis
  - Kernel module integrity checking
  - Syscall table hook detection
  - Network backdoor identification
  - Boot sector/UEFI analysis
  - Container escape detection
  - Persistence mechanism scanning
  - Deep memory signature analysis

- **Subtle & Professional**
  - Clean, minimal output
  - Quiet mode for automation
  - JSON output support
  - Log file generation
  - Exit codes for scripting

## Build

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-rkhunt
cd nullsec-rkhunt

# Compile
make
# or
gcc -O2 -Wall -D_GNU_SOURCE -o rkhunt src/rkhunt.c -lpthread

# Install (optional)
sudo make install
```

## Usage

```bash
# Full comprehensive scan
sudo ./rkhunt -a

# Quick scan (processes, modules, preload)
sudo ./rkhunt -q

# Specific checks
sudo ./rkhunt -m          # Kernel modules only
sudo ./rkhunt -n          # Network analysis
sudo ./rkhunt -s          # Syscall table
sudo ./rkhunt -b          # Boot/UEFI integrity
sudo ./rkhunt -c          # Container security

# Output options
sudo ./rkhunt -a -v            # Verbose
sudo ./rkhunt -a -Q            # Quiet (alerts only)
sudo ./rkhunt -a -l scan.log   # Log to file
```

## Rootkit Database

### LKM Rootkits (Kernel)
Singularity, Reptile, Diamorphine, Suterusu, Kovid, Nurupo, BDVl, BEURK, Azazel, Jynx2, Vlany, Horsepill, Drovorub, Facefish, SkidMap, Pandora, Umbreon, Adore-NG, Knark, SucKIT, and 50+ more

### Userland Rootkits
Jynx, Azazel, Vlany, BEURK, BDVl, LibProcessHider, Apache Backdoor, Erebus, LD_Poison, and 20+ more

### Bootkits/UEFI
BlackLotus, MoonBounce, CosmicStrand, LoJax, TrickBot MBR, Rovnix, TDL4, Alureon, and 25+ more

### Container/Cloud
Doki, Kinsing, TeamTNT, Graboid, Hildegard, Siloscape, AzureScape, and 15+ more

## Exit Codes

- `0` - System clean
- `1` - Potential infection detected
- `2` - Critical findings (high confidence)

## Requirements

- Linux (kernel 3.x+)
- GCC
- Root privileges (recommended)

## License

MIT License
