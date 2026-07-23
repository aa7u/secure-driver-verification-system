# 🛡️ Secure Driver Verification System (SDVS)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Focus](https://img.shields.io/badge/Focus-Kernel%20Security-blue)](#)

An open-source security tool designed to audit, verify, and assess system drivers before installation. Operating at the Kernel Level, device drivers possess elevated system privileges—making untrusted or unsigned drivers a severe security risk. **SDVS** mitigates supply chain risks by inspecting driver signatures, vendor sources, and integrity before execution.

---

## ✨ Key Features

* 🔍 **System Driver Auditing:** Scans and inventories currently installed device drivers.
* ✍️ **Digital Signature Verification:** Validates Authenticode signatures and cryptographic integrity.
* 🌐 **Official Vendor Cross-Checking:** Fetches and verifies driver metadata against official sources (Intel, AMD, NVIDIA, etc.).
* 🏷️ **Release Channel Inspection:** Identifies whether a driver package is Stable, WHQL-certified, or Beta/Experimental.
* ⚠️ **Risk Assessment Matrix:** Evaluates drivers and assigns an actionable security rating (**Low**, **Medium**, or **High Risk**).
* 💡 **Actionable Recommendations:** Provides clear safety guidance to end-users before proceeding with installation.

---

## 🚀 Quick Start

### Prerequisites
* OS: Windows 10/11
* Python 3.10+
* Administrative Privileges (required for querying driver signatures)

### Installation & Run

```bash
# Clone the repository
git clone https://github.com/aa7u/secure-driver-verification-system.git
# Navigate into the project directory
cd secure-driver-verification-system

# Install dependencies
pip install -r requirements.txt

# Run the system
python sdvs/main.py
