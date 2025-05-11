# CloudGhost 👻

**Unearthing Vanished Cloud Assets & Subdomain Takeovers**

---

## 🚀 Introduction

In the ever-expanding digital landscape, domain names and subdomains are constantly created, moved, and sometimes, unfortunately, forgotten. When a subdomain's DNS record (like a CNAME) points to a cloud service or SaaS provider that is later deprovisioned or misconfigured, it leaves behind a "ghost" - a dangling DNS entry that can be claimed by an attacker.

CloudGhost is your tool to hunt down these digital specters. It's a powerful, modular, and fast subdomain takeover detection tool designed to illuminate the forgotten corners of your (or your target's, with permission!) online presence.

Leveraging multiple intelligence sources for subdomain discovery and armed with a robust fingerprint database, CloudGhost helps you identify potential takeover vulnerabilities before they become security incidents.

---

## ✨ Key Features

* **Multi-Input:** Scan a single domain, a list of domains, or a pre-compiled list of subdomains.
* **Intelligent Recon:** Employs a concurrent pipeline using **Subfinder**, **Assetfinder** (in deep mode), **crt.sh** certificate logs, and **AzSubEnum** (for Azure specifics) to find hidden subdomains.
* **Blazing Fast Detection:** Checks discovered subdomains concurrently using threading for maximum speed.
* **Precision Fingerprinting:** Utilizes a curated database of known cloud and SaaS service fingerprints to accurately identify vulnerable states based on CNAMEs and HTTP responses.
* **Clear Categorization:** Provides actionable results classified into intuitive categories (YES, HIGH CHANCE, LOW CHANCE, NO, ERROR).
* **Exportable Results:** Saves all findings to a detailed CSV file for easy analysis and reporting.
* **Modular Design:** Code is organized into logical files (`utils.py`, `recon.py`, `takeover.py`) for maintainability and clarity.

---

## 📁 Project Files

* `utils.py`: The brains of the operation - argument parsing, orchestration, and general helpers (running commands, crt.sh, CSV export). **Run this file!**
* `recon.py`: The hunter - manages and runs external tools concurrently to find subdomains.
* `takeover.py`: The detective - contains the fingerprint database and logic for checking subdomains and categorizing takeover potential.

Make sure all three files are together in the same directory!

---

## 🛠️ Prerequisites

Before unleashing CloudGhost, ensure you have the following installed:

1.  **Python 3.x:** The core language. Using a `venv` is highly recommended!
2.  **Python Libraries:**
    ```bash
    pip install requests dnspython
    ```
3.  **Go:** Required for installing some of the best recon tools. Download from [golang.org/dl](https://golang.golang.org/dl/). **Crucially, add Go's `bin` directory to your system's PATH!**
4.  **External Recon Tools (Install via Go):**
    * **Subfinder:** `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
    * **Assetfinder:** `go install github.com/tomnomnom/assetfinder@latest`
5.  **AzSubEnum (Optional, for Azure):** A Python tool. Clone and get ready:
    ```bash
    git clone [https://github.com/yuyudhn/AzSubEnum.git](https://github.com/yuyudhn/AzSubEnum.git)
    cd AzSubEnum
    pip install -r requirements.txt # (May already be satisfied if you installed requests/dnspython)
    ```
    * Ensure `azsubenum.py` is executable (Linux/macOS: `chmod +x azsubenum.py`) and accessible via your PATH or by running `python3 azsubenum.py` from the correct directory.

**Verification:** Open a new terminal after installation and check if `subfinder -h`, `assetfinder -h`, and `python3 azsubenum.py -h` (or `azsubenum.py -h`) work!

---

## 🚀 Quick Start & Usage

Navigate to the directory containing the project files in your terminal.

```bash
python3 utils.py [arguments]
