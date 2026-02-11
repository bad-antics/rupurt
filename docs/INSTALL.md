# rupurt Installation

## From Source
```bash
git clone https://github.com/bad-antics/rupurt
cd rupurt
make
sudo make install
```

## Dependencies
```bash
# Debian/Ubuntu
sudo apt install build-essential linux-headers-$(uname -r) libelf-dev libbpf-dev

# Fedora/RHEL
sudo dnf install gcc kernel-devel elfutils-libelf-devel libbpf-devel

# Arch
sudo pacman -S base-devel linux-headers libelf libbpf
```

## Verify Installation
```bash
rupurt --version
sudo rupurt --quick  # Run quick scan to verify
```
