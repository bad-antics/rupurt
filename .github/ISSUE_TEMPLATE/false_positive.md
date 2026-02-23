---
name: False Positive Report
about: Report a detection that is incorrectly flagged as suspicious
title: "[False Positive] "
labels: false-positive
assignees: bad-antics
---

## Finding Details

**rupurt version:**
<!-- Output of: rupurt --version -->

**Kernel version:**
<!-- Output of: uname -r -->

**OS/Distribution:**
<!-- e.g., Ubuntu 24.04, Debian 13, NullSec Linux 5.0 -->

## Detection Output

Paste the `--verbose --json` output for the flagged finding:

```json

```

## What the flagged item actually is

<!-- Explain what the process/file/module is and why it's legitimate -->

## How to reproduce

```bash
# Commands to reproduce the false positive
sudo rupurt --full --verbose
```

## Additional context

<!-- Any other information that might help -->
