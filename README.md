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
3.  **Go:** Required for installing some of the best recon tools. Download from [golang.org/dl](https://golang.golang.dl/). **Crucially, add Go's `bin` directory to your system's PATH!**
4.  **External Recon Tools (Install via Go):**
    * **Subfinder:** `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
    * **Assetfinder:** `go install github.com/tomnomnom/assetfinder@latest`
5.  **AzSubEnum (Optional, for Azure):** A Python tool. Clone and get ready:
    ```bash
    git clone https://github.com/yuyudhn/AzSubEnum.git
    cd AzSubEnum
    pip install -r requirements.txt # (May already be satisfied if you installed requests/dnspython)
    ```
    * Ensure `azsubenum.py` is executable (Linux/macOS: `chmod +x azsubenum.py`) and accessible via your PATH or by running `python3 azsubenum.py` from the correct directory.

**Verification:** Open a new terminal after installation and check if `subfinder -h`, `assetfinder -h`, and `python3 azsubenum.py -h` (or `azsubenum.py -h` if executable/in PATH) work!

---

## 🚀 Quick Start & Usage

Navigate to the directory containing the project files in your terminal.

```bash
python3 utils.py [arguments]
Choose ONE Input Method:

-d <domain> or --domain <domain>: Scan a single root domain (e.g., target.com).
-i <file> or --input <file>: Scan subdomains from a list file (one per line). Skips root domain recon.
--domain-list <file>: Scan multiple root domains from a list file (one per line). Runs full process for each.
Recon Options (Use with -d or --domain-list):

--mode <quick|deep>:
quick (default): Subfinder + crt.sh
deep: Adds Assetfinder.
--azure-base <base_name>: Optional. Your target's Azure tenant/base name (e.g., acmecorp). Enables AzSubEnum.
--subfinder-timeout <seconds>: Adjust Subfinder timeout (default: 120).
--assetfinder-timeout <seconds>: Adjust Assetfinder timeout (default: 180).
--azure-enum-timeout <seconds>: Adjust AzSubEnum timeout (default: 180).
Output Option:

-o <filename> or --output <filename>: Specify output CSV file (default: subdomains_takeover_status.csv).
🧙‍♂️ Examples:

Bash

# Simple quick scan of a single domain
python3 utils.py --domain example.com

# Deep scan and save results to a specific file
python3 utils.py --domain example.com --mode deep --output example_results.csv

# Deep scan including Azure enumeration (replace with actual base name!)
python3 utils.py --domain example.com --mode deep --azure-base acmetech --output example_azure_results.csv

# Scan subdomains from a pre-existing list
python3 utils.py --input my_known_subdomains.txt --output scanned_list_results.csv

# Scan subdomains from a list and add Azure enumeration results
python3 utils.py --input my_known_subdomains.txt --azure-base acmetech --output combined_results.csv

# Scan multiple domains listed in a file (my_domains.txt) using deep mode
python3 utils.py --domain-list my_domains.txt --mode deep --output batch_scan_results.csv
📊 Understanding the Output
CloudGhost provides a summary in the console and a detailed CSV file.

The CSV (subdomains_takeover_status.csv by default) contains:

subdomain: The tested subdomain.
cname: The resolved CNAME (or N/A, ERROR).
service: Identified service (or Unknown, Scan Error).
status_code: HTTP Status or Unreachable/ERROR.
takeover_possible: The Verdict!
The Verdict Categories:

🟢 YES: HIGH CONFIDENCE - Matches a known vulnerable fingerprint pattern. Manual verification highly recommended.
🟡 HIGH CHANCE: LIKELY VULNERABLE - Has a dangling CNAME pointing to an external service, but didn't match a specific 'YES' pattern. Requires manual investigation.
🔵 LOW CHANCE: CHECK DNS - No CNAME, but also unreachable. Indicates potential DNS issues, but not a CNAME takeover.
⚫ NO: SECURE - No CNAME, and the subdomain is reachable (likely A/AAAA record). No immediate CNAME takeover risk.
🔴 ERROR: Scan encountered an issue processing this subdomain.
🔮 Future Updates & Improvements
CloudGhost is a community-driven project, and there are many exciting avenues for future development to make it even more powerful and comprehensive. Here are some areas we plan to explore and welcome contributions on:

Expanding the Fingerprint Database: This is a continuous effort! We aim to significantly increase the number of supported cloud providers and SaaS services by adding new CNAME patterns and reliable detection indicators (status codes, body content, headers). Contributions for new fingerprints are highly valued.
Integrating More Reconnaissance Sources: Beyond the current tools, we can add support for:
Active brute-forcing and permutation techniques using tools like massdns combined with effective wordlists.
Leveraging public APIs from services like VirusTotal, SecurityTrails, Shodan, Censys, etc., for richer passive data (requires API key management).
ASN enumeration to map related IP ranges.
Enhancing Detection Logic:
Implementing more sophisticated analysis of HTTP responses, including checking response headers and analyzing page structure beyond simple string/regex matches.
Improving handling of redirects and chained CNAMEs.
Developing a confidence scoring system for findings.
Supporting Other Takeover Types: Extending detection beyond CNAMEs to identify vulnerable NS, A/AAAA, or MX records pointing to claimable resources.
Configuration Management: Implementing a configuration file (e.g., YAML or INI) to easily manage settings like timeouts, thread counts, enabled/disabled recon sources, and API keys.
Output Flexibility: Adding support for additional output formats like JSON for easier integration with other tools or workflows.
Performance Optimizations: Continuously seeking ways to improve the speed and efficiency of network requests and data processing, especially for large-scale scans.
Improved Error Handling and Reporting: Making the tool more robust against network issues and providing clearer error messages.
🤝 How to Contribute
We encourage and welcome contributions from the community! Whether you're a seasoned security researcher, a developer, or just getting started, your help is valuable.

Here are some ways you can contribute:

Star the Repository: Show your support and help increase the project's visibility!
Report Issues: If you find a bug, encounter an error, or have a suggestion for improvement, please open an issue on the GitHub repository. Provide as much detail as possible (steps to reproduce, error messages, environment details).
Suggest New Features: Have an idea for a feature that would make CloudGhost better? Open an issue to describe your idea and discuss its potential implementation.
Add New Fingerprints: This is one of the most impactful ways to contribute! Research vulnerable cloud/SaaS services, identify their CNAME patterns and reliable takeover indicators (status codes, unique body content, headers). Fork the repository, add the new fingerprint(s) to the FINGERPRINT_DB in takeover.py, and submit a Pull Request with your changes. Include links to your research or proof-of-concept if possible.
Improve Code: Fork the repository, create a new branch for your changes, and submit a Pull Request. This could involve:
Implementing a feature from the "Future Updates" list or a new idea.
Refactoring existing code for better readability or performance.
Improving documentation or adding comments.
Fixing bugs. Please follow a reasonable code style (like PEP 8 for Python) and include tests if applicable.
Documentation: Help improve the README, add usage examples, or create more detailed documentation for specific parts of the tool.
Testing: Run CloudGhost on various targets (with permission!) and share your findings (especially new vulnerable services or potential false positives/negatives) by opening issues.
We appreciate your time and effort in contributing to CloudGhost!

📄 License
This project is licensed under the MIT License.

A short and simple permissive license with conditions only requiring preservation of copyright and license notices. 1  Licensed works, modifications, and larger works may be distributed under different terms and without source code.   
 1. 
lifescience.opensource.epam.com
lifescience.opensource.epam.com

Plaintext

MIT License

Copyright (c) [Year] [Your Name/Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
(Replace [Year] and [Your Name/Organization] above with your details)

⚠️ Disclaimer
This tool is intended for ethical security testing and educational purposes ONLY. You must ensure you have explicit permission from the domain owner before performing any scans. Unauthorized scanning may violate laws and regulations.

Subdomain takeover detection is not an exact science. Results, especially those categorized as HIGH CHANCE, require manual verification. The tool may not find all vulnerabilities and might report false positives. Use responsibly and ethically!
