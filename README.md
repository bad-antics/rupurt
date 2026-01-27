# NullSec rkhunt 

> Rootkit hunter detecting hidden processes, modules, and system hooks

![Language](https://img.shields.io/badge/Language-C-red)
![Platform](https://img.shields.io/badge/Platform-Linux-black)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

Part of the NullSec security toolkit. Written in **C**.

## Features

- Hidden process detection
- Kernel module analysis
- LD_PRELOAD hook detection
- Rootkit signature scanning
- System integrity verification
- Network anomaly detection

## Installation

```bash
make
sudo make install
```

## Usage

```bash
rkhunt --help               # Show help
rkhunt -a                   # Full scan
rkhunt -p -m                # Processes + modules
rkhunt -a -v                # Verbose scan
```

## Author

**bad-antics** - NullSec Project

## License

MIT License
