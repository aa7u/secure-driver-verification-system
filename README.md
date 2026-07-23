# 🛡️ Secure Driver Verification System (SDVS)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/aa7u/secure-driver-verification-system/actions/workflows/tests.yml/badge.svg)](https://github.com/aa7u/secure-driver-verification-system/actions)
[![Focus](https://img.shields.io/badge/Focus-Kernel%20Security-blue)](#)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](#)

An open-source security tool designed to audit, verify, and assess system drivers before installation. Operating at the Kernel Level, device drivers possess elevated system privileges—making untrusted or unsigned drivers a severe security risk. **SDVS** mitigates supply chain risks by inspecting driver signatures, vendor sources, blocklists, and integrity before execution.

---

## 🎬 Live Audit Demonstration

![SDVS Demo](assets/demo.gif)

---

## 🏛️ Design Philosophy

SDVS is built upon three core security principles tailored for modern kernel-space defenses:

* **Zero Trust in Kernel Space:** No driver is trusted by default—even if digitally signed—until its SHA-256 hash is verified against known vulnerable and exploited driver databases.
* **Defense-in-Depth Assessment:** Security evaluation moves beyond simple PE header inspection into multi-layered risk scoring (Signature + Microsoft Blocklists + Beta/Test Flags).
* **Developer-Centric Security Audit:** High-speed CLI execution combined with actionable recommendations, enabling engineers and threat analysts to assess system integrity effortlessly.

---

## ✨ Key Features

* 🔍 **System Driver Auditing:** Scans and inventories currently installed Windows kernel drivers.
* ✍️ **Digital Signature Verification:** Parses PE Security Directories (`IMAGE_DIRECTORY_ENTRY_SECURITY`) to validate Authenticode digital signatures.
* 🛡️ **Microsoft Vulnerable Driver Blocklist:** Integrates SHA-256 matching engine to detect exploited drivers used in Bring Your Own Vulnerable Driver (BYOVD) attacks.
* 🔐 **Cryptographic Verification:** Computes accurate SHA-256 binary hashes for file integrity checks.
* 🎨 **Interactive Rich CLI:** Uses progress indicators and color-coded risk assessment tables.
* 📄 **Multi-Format Exporting:** Supports exporting full audit reports to structured `JSON` and styled `HTML` formats.
* ⚠️ **Risk Assessment Matrix:** Evaluates drivers and dynamically assigns security ratings (**LOW RISK**, **MEDIUM RISK**, **HIGH RISK**, or **CRITICAL RISK**).
* 💡 **Actionable Recommendations:** Provides clear safety guidance before loading drivers into system kernel space.

---

## 🗺️ Strategic Capabilities Roadmap

| Level | Version | Capability / Feature | Status |
| :--- | :--- | :--- | :--- |
| **Level 1** | `v0.1.0` - `v0.2.0` | PE Header Parsing, Digital Signature Verification, Rich CLI & Exporting (HTML/JSON) | **Completed** ✅ |
| **Level 2** | `v0.3.0` | **Risk Assessment Engine**, Microsoft Vulnerable Driver Blocklist Integration, `CRITICAL RISK` BYOVD Detection | **Completed** ✅ |
| **Level 3** | `v0.4.0` | Custom Directory Scanning CLI Flags (`--path`), Dynamic Heuristic Rules Engine | **In Progress** ⏳ |
| **Level 4** | `v1.0.0` | Kernel Memory Inspection, Real-Time Driver Load Monitoring, VirusTotal API Integration | **Planned** 📅 |

---

## 🚀 Quick Start

### Prerequisites
* OS: Windows 10/11
* Python 3.10+
* Administrative Privileges (Recommended for deep system driver reads)

### Installation & Execution

```powershell
# Clone the repository
git clone [https://github.com/aa7u/secure-driver-verification-system.git](https://github.com/aa7u/secure-driver-verification-system.git)

# Navigate into the project directory
cd secure-driver-verification-system

# Set up virtual environment & install dependencies
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run interactive CLI scan
python main.py

# Run scan with HTML report export
python main.py --limit 10 --export html
