# EPSS Intel WebApp (v2.0.0)

## Project Overview

This document describes the **EPSS Intel WebApp**, a web-based tool designed to fetch, analyze, and display Exploit Prediction Scoring System (EPSS) scores and detailed Common Vulnerability Enumeration (CVE) information through a user-friendly web interface.

This project is a complete refactoring of the original `epss-intel` CLI tool, transforming its functionality from a terminal-based output to a local HTML host display. The original CLI tool's core logic for fetching data from EPSS, CISA KEV (Known Exploited Vulnerabilities), NVD (National Vulnerability Database), and CVE Services APIs has been preserved and adapted for the web environment.

**Authorship:**
*   **Original CLI Tool Concept/Initial Version:** Omar Santos (@santosomar)
*   **Web App Refactoring and Re-Authorship:** Jonathan Beals
*   **Project Created With:** Gemini CLI
*   **Version:** 2.0.0 (Web App Integration)

## Features

*   **Web-based Interface:** Access the EPSS Intel functionality through your web browser.
*   **CVE Input:** Easily input single or multiple CVE IDs via a text area (comma-separated) or by uploading a newline-separated text file.
*   **Comprehensive Data Display:** View EPSS scores, percentiles, CISA KEV status, CVE titles, CVSS scores, severities, and descriptions in a clear, tabular format.
*   **Color-Coded EPSS Scores:** Visual cues for high (red), medium (orange), and low (green) EPSS scores.
*   **Static Assets:** Basic CSS for a clean and readable interface.
*   **Python Bottle Framework:** Utilizes a lightweight Python web framework for serving the application.

## Installation Guide

This guide assumes you have Python 3.8+ and `pipenv` installed on your system.

**Prerequisites Installation:**

*   **Python 3.8+:** Download from [python.org](https://www.python.org/downloads/).
*   **pip (Python package installer):** Usually comes with Python. Verify with `python3 -m pip --version`.
*   **pipenv:** Install globally using `pip`:
    ```bash
    python3 -m pip install --user pipenv
    ```
    Ensure `pipenv`'s executable path is in your system's PATH. You might need to add `~/.local/bin` to your PATH environment variable. Refer to `pipenv`'s official installation guide for details.

1.  **Navigate to the project root directory:**
    Open your terminal and go to the directory where you cloned or extracted the `epss-client` project (this directory should contain `requirements.txt`, `Pipfile`, and the `epss_intel/` subdirectory).
    ```bash
    cd path/to/your/epss-client-project
    ```

2.  **Install project dependencies using `pipenv`:**
    This command will create a virtual environment for the project (if one doesn't exist) and install all necessary Python packages (`requests`, `bottle`, `rich`).
    ```bash
    pipenv install requests bottle rich
    ```
    *   **Alternative (activate shell):** You can also activate the virtual environment first by running `pipenv shell` in your project root, and then execute `python3 epss_intel/epss_intel_webapp.py`.
    *   **Note on `sudo`:** If you encounter permission errors during `pipenv install`, you may have to use `sudo pipenv install requests bottle rich`. However, ideally, `pipenv` environments should be user-owned. If you consistently need `sudo` for `pipenv` commands, consider fixing your system's Python/pipenv permissions for a more sustainable development setup.

## Usage

1.  **Start the Web Server:**
    From your project root directory, run the web application using `pipenv`:
    ```bash
    pipenv run python3 epss_intel/epss_intel_webapp.py
    ```
    You should see output similar to `Bottle vX.X.X server starting up (using WsgiRefServer)... Listening on http://localhost:8080/`.
    *   **Important:** If a server instance is already running, stop it first by pressing `Ctrl+C` in the terminal where it's running.

2.  **Access the Web App:**
    Open your web browser and navigate to:
    ```
    http://localhost:8080/
    ```
    *   **Port 8080 Inaccessible?** If you are unable to access `http://localhost:8080/`, ensure that port 8080 is not blocked by a firewall on your system.


3.  **Enter CVEs:**
    On the web page, you will find a text area. Enter CVE IDs either one per line or comma-separated (e.g., `CVE-2021-44228, CVE-2023-2825`).
    You can also use the "Upload CVE File" option to provide a text file with CVEs (one per line).

4.  **Get EPSS Scores:**
    Click the "Get EPSS Scores" button. The application will fetch the data and display the results in a table on the same page.

## Project Structure

```
[Your-Project-Root-Directory]/
├── epss_intel/
│   └── epss_intel_webapp.py    # The refactored web application script
│   └── epss_intel.py           # Original CLI script (left intact)
├── views/
│   └── index.tpl               # HTML template for the web interface
├── static/
│   └── style.css               # CSS for styling the web interface
├── requirements.txt
└── Pipfile
└── Pipfile.lock
```

## Troubleshooting & Notes

*   **`ModuleNotFoundError`:** Ensure you are in the correct directory (`epss-client` project directory) and have run `pipenv install` to install all dependencies. If issues persist, try `pipenv --rm` followed by `pipenv install` to reset the virtual environment.
*   **`TemplateError: Template 'index' not found.`:** This was a tricky issue. It's resolved in `epss_intel_webapp.py` by ensuring `bottle.TEMPLATE_PATH` is explicitly set to the correct absolute path of the `views` directory and passing just the template name (`'index'`) to the `template()` function.
*   **"500 Internal Server Error":** Check the console where your web server is running (`pipenv run ...` terminal). Detailed Python tracebacks will appear there, which are crucial for diagnosing the error.
*   **Stale or Incorrect Data:** If the EPSS scores or CVE details appear outdated or incorrect, you might need to clear the local cache files. These are typically located in your home directory:
    *   `~/.epss_cisa_kev.json`
    *   `~/.epss_cve_cache.json`
    Deleting these files will force the application to fetch fresh data from the APIs.

---

*Generated by Jenny, orchestrated with Sage (Researcher) and Forge (Engineer)*