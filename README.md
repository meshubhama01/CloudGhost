Markdown

# CloudGhost 👻

**Find & Classify Subdomain Takeovers**

---

## ✨ Quick Overview

CloudGhost is a Python tool to find potential subdomain takeover vulnerabilities. It discovers subdomains using multiple sources and checks them against known service fingerprints to classify takeover risk.

---

## 🚀 Features

* **Multiple Inputs:** Scan a single domain, domain list file, or subdomain list file.
* **Smart Recon:** Uses Subfinder, Assetfinder (deep mode), crt.sh, and optional AzSubEnum (for Azure). Runs concurrently.
* **Fast Checking:** Concurrently checks subdomains for takeover signs.
* **Fingerprint Database:** Matches CNAMEs and HTTP responses to identify vulnerabilities.
* **Clear Results:** Categorizes potential takeovers (YES, HIGH CHANCE, LOW CHANCE, NO, ERROR).
* **CSV Output:** Saves results to a file.
* **Modular:** Code is split into `utils.py`, `recon.py`, `takeover.py`.

---

## 🛠️ Setup

1.  **Get Code:** Save `utils.py`, `recon.py`, and `takeover.py` in the same folder.
2.  **Install Python Deps:**
    ```bash
    pip install requests dnspython
    ```
3.  **Install Go:** Follow [golang.org/dl](https://golang.golang.dl/) and add Go bin to PATH.
4.  **Install Go Tools:**
    ```bash
    go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
    go install [github.com/tomnomnom/assetfinder@latest](https://github.com/tomnomnom/assetfinder@latest)
    ```
5.  **Install AzSubEnum (Optional for Azure):**
    ```bash
    git clone [https://github.com/yuyudhn/AzSubEnum.git](https://github.com/yuyudhn/AzSubEnum.git)
    # Install AzSubEnum Python deps if needed: pip install -r AzSubEnum/requirements.txt
    # Ensure azsubenum.py is executable & in PATH or runnable via python3
    ```
6.  **Verify:** Check `subfinder -h`, `assetfinder -h`, `python3 azsubenum.py -h` work in your terminal.

---

## 💡 Usage

Run `utils.py` from your terminal:

```bash
python3 utils.py [arguments]
Choose ONE Input:

-d <domain>: Scan domain.com (runs recon).
-i <file>: Scan subdomains from file.txt (skips recon).
--domain-list <file>: Scan each domain in file.txt (runs recon per domain).
Key Options (Use with -d or --domain-list):

--mode <quick|deep>: quick (Subfinder+crt.sh) or deep (Adds Assetfinder). Default: quick.
--azure-base <base_name>: Your target's Azure name (e.g., acmecorp). Enables AzSubEnum.
Other Options:

-o <filename>: Output CSV file (default: subdomains_takeover_status.csv).
--subfinder-timeout <sec>: Timeout for Subfinder (default: 120).
--assetfinder-timeout <sec>: Timeout for Assetfinder (default: 180).
--azure-enum-timeout <sec>: Timeout for AzSubEnum (default: 180).
🎯 Examples:

Bash

# Scan single domain (quick mode)
python3 utils.py --domain example.com

# Scan single domain (deep mode) & save
python3 utils.py --domain example.com --mode deep -o results.csv

# Scan single domain (deep mode) & use Azure recon
python3 utils.py --domain example.com --mode deep --azure-base mycorp

# Scan subdomains from a list file
python3 utils.py --input my_subs.txt

# Scan domains from a list file (deep mode)
python3 utils.py --domain-list my_domains.txt --mode deep
📊 Output & Categories
Results saved to CSV. takeover_possible column shows the status:

🟢 YES: Confirmed vulnerability based on fingerprint match.
🟡 HIGH CHANCE: Dangling CNAME detected, points externally, but specific vuln pattern not matched. Needs manual check.
🔵 LOW CHANCE: No CNAME & unreachable. Not a CNAME takeover.
⚫ NO: No CNAME & reachable. Healthy record.
🔴 ERROR: Scan error for this subdomain.
🔮 Future Ideas
Expand fingerprint database.
Add active recon (brute-force/permutation).
Support NS/A/AAAA takeover types.
Config file support.
🤝 Contribute
Contributions are welcome!

Report bugs/suggest features via Issues.
Add new fingerprints to takeover.py and submit a Pull Request.
Improve code and submit a Pull Request.
📄 License
[This project is licensed under the MIT License. (See LICENSE file for details)]

⚠️ Disclaimer
For ethical security testing ONLY with explicit permission. Results need manual verification. Use responsibly.

