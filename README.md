# EPSS Intel: Advanced Vulnerability Intelligence CLI

**EPSS Intel** is a powerful command-line tool designed for security researchers, SOC analysts, and vulnerability management teams. It enriches raw CVE data with real-time **EPSS (Exploit Prediction Scoring System)** scores, **CISA KEV (Known Exploited Vulnerabilities)** status, and rich metadata from the **CVE Services API (v5)**.

## 🚀 Key Features

### 🛡️ Multi-Source Vulnerability Intelligence
- **EPSS Scores:** Fetch real-time exploit probability and percentile rankings from the FIRST API.
- **CISA KEV Integration:** Automatically cross-reference CVEs with CISA's "Known Exploited Vulnerabilities" list to identify active exploitation in the wild.
- **Rich Metadata:** Fetch CVE Titles, CVSS 3.x scores, and Severity rankings directly from the modern CVE Services API (v5).
- **NVD Descriptions:** Optional fallback to fetch detailed vulnerability descriptions from the NIST NVD API.

### ⚡ High-Performance Architecture
- **Parallel Fetching:** Uses multi-threaded execution (`ThreadPoolExecutor`) to fetch metadata for dozens of CVEs concurrently.
- **Local Caching:** Implements a persistent local cache (`~/.epss_cve_cache.json`) to store metadata and descriptions, making subsequent lookups instantaneous.
- **Intelligent Batching:** Automatically handles API rate limits and URL character constraints for large batch queries.

### 📊 Advanced Data Management
- **Filtering:** Focus on high-risk items with `--min-epss`, `--min-cvss`, or `--kev-only` flags.
- **Sorting:** Prioritize your remediation list by sorting results by EPSS score, CVSS score, or CVE ID.
- **Summary Statistics:** Every report concludes with a comprehensive "Bottom Line" summary, including severity breakdowns and active exploitation counts.

### 🎨 Modern UI & Export
- **Rich Table Output:** Color-coded terminal tables with clear legends and status indicators.
- **Flexible Export:** Save results directly to **CSV** or **JSON** for integration with other security workflows.

---

## 📥 Installation

The most reliable way to install **EPSS Intel** is using `pipx`, which ensures the tool and its dependencies (like `requests` and `rich`) are installed in an isolated environment and made available as a global command.

### **1. Install pipx (if not already present)**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install pipx
pipx ensurepath
```

### **2. Install EPSS Intel**
Clone the repository and install it in "editable" mode so that any future updates to the source code are immediately reflected in the global command:

```bash
# Clone the fork
git clone https://github.com/SigTL/epss-client.git
cd epss-client

# Install globally in editable mode
pipx install --editable . --force
```

### **3. Verify Installation**
Check that the command is available and the help menu displays correctly:
```bash
epss-intel --help
```

---

## 🛠️ Usage

### **Core Command**
```bash
epss-intel [CVE-ID] [OPTIONS]
```

### **Primary Options**
| Option | Short | Description |
| :--- | :--- | :--- |
| `--cve-details` | `-d` | Fetch Title, CVSS, Severity, and Description (Parallel & Cached). |
| `--list` | `-l` | Comma-separated list of CVE IDs. |
| `--file` | `-f` | Path to a file containing one CVE ID per line. |
| `--sort` | | Sort results by `epss`, `cvss`, or `cve`. |
| `--min-epss` | | Filter results by minimum EPSS probability (0.0 - 1.0). |
| `--kev-only` | | Only show vulnerabilities on the CISA KEV list. |
| `--output` | `-o` | Save results to a file (CSV or JSON). |
| `--include-desc`| | Force a description fetch specifically from NVD (slow). |

### **Examples**

#### **1. Quick Risk Assessment**
Fetch rich intelligence for a critical vulnerability:
```bash
epss-intel CVE-2021-44228 -d
```

#### **2. Batch Processing & Sorting**
Analyze a list of CVEs and sort them by exploit probability:
```bash
epss-intel -l CVE-2024-21626,CVE-2023-38831,CVE-2017-0144 -d --sort epss
```

#### **3. High-Priority Filtering**
Show only actively exploited vulnerabilities from a file:
```bash
epss-intel -f vulnerabilities.txt -d --kev-only
```

#### **4. Data Export**
Export filtered results to a JSON file for further analysis:
```bash
epss-intel -f scan_results.txt -d --min-epss 0.05 --output report.json
```

---

## 📋 Requirements
- Python 3.8+
- `requests`
- `rich`

---

## ⚖️ License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---
*Author: Omar Santos (@santosomar) | Enhanced by Forge (Gemini CLI Engineer)*
