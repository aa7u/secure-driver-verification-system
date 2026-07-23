# 🛡️ Secure Driver Verification System (SDVS)

[![Build Status](https://github.com/aa7u/secure-driver-verification-system/actions/workflows/ci.yml/badge.svg)](https://github.com/aa7u/secure-driver-verification-system/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Secure Driver Verification System (SDVS)** is a Windows kernel driver auditing and threat intelligence tool built for security researchers, incident responders, and system administrators. It analyzes installed Windows kernel drivers (`.sys`), calculates trust scores, verifies digital signatures, checks known vulnerable driver blocklists, evaluates custom policy rules, and performs YARA-based threat detection.

---

# ✨ Features

- 🔍 **PE Analysis**
  - Parses PE headers and sections
  - Calculates Shannon entropy
  - Extracts PDB/debug paths

- 🔐 **Digital Signature Verification**
  - Verifies Authenticode signatures
  - Extracts certificate issuer and subject information

- 🛡️ **Known Vulnerable Driver Detection**
  - SHA-256 hash generation
  - Microsoft vulnerable driver blocklist support
  - LOLDrivers blocklist support

- ⚙️ **Custom Policy Engine**
  - YAML-based rule configuration
  - No code modifications required

- 🧪 **YARA Threat Scanning**
  - Detects suspicious patterns
  - Supports custom YARA rules

- 📊 **Report Generation**
  - Interactive HTML dashboard
  - JSON export
  - Risk score visualization using Chart.js

- 💻 **Command-Line Interface**
  - Simple CLI with configurable scan limits
  - Packaged as the `sdvs` command

---

# 📁 Repository Structure

```text
secure-driver-verification-system/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── src/
│   ├── rules/
│   │   └── kernel_suspicious.yar
│   │
│   ├── blocklist.py
│   ├── cert_verifier.py
│   ├── collector.py
│   ├── evaluator.py
│   ├── main.py
│   ├── rule_engine.py
│   ├── rules.yaml
│   ├── verifier.py
│   └── yara_verifier.py
│
├── tests/
│   └── test_sdvs.py
│
├── pyproject.toml
├── README.md
└── LICENSE
```

---

# 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/aa7u/secure-driver-verification-system.git
cd secure-driver-verification-system
```

Install the project in editable mode:

```bash
pip install -e .
```

---

# ▶️ Usage

Scan the first 5 installed kernel drivers:

```bash
sdvs --limit 5
```

Generate an interactive HTML report:

```bash
sdvs --limit 10 --export html
```

Export scan results as JSON:

```bash
sdvs --limit 10 --export json
```

---

# 🧪 Running Tests

Run the test suite using pytest:

```bash
python -m pytest
```

---

# 📦 Requirements

- Python 3.10+
- Windows
- Administrator privileges (recommended for full driver enumeration)

---

# 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.