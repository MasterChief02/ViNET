# ViNET Automated Testing Framework

This directory contains the modular testing framework for ViNET.

## Overview

The testing suite is built around `master.py`, which provides the base `Device` class and high-level orchestrators. Individual test cases are implemented as standalone scripts that import these capabilities.

## Directory Structure

- `master.py`: **Support Module**. Provides the environment setup, device management, and decorators used by other scripts.
- `config.py`: Configuration loader for `config.yaml`.
- `config.yaml.example`: Template for local setup.
- `sites/`: Text files containing URL lists for website tests.
- `test_*.py`: **Test Scripts**. These are the primary entry points for running tests (e.g., `test_websites.py`, `test_vilte.py`).

## Configuration

To avoid hardcoding sensitive information, setup a local `config.yaml`:

1.  `cp config.yaml.example config.yaml`
2.  Update `config.yaml` with your device serials and phone numbers.
3.  Set the `active_device_pair` to choose your target hardware.

## Running Tests

Run the specific test script for the application you wish to evaluate.

### Example: Website Benchmarking
```bash
python3 test_websites.py --type paper_custom --isp <ISP_NAME>
```

### Example: ViLTE Analysis
```bash
python3 test_vilte.py --carrier <CARRIER_NAME>
```
