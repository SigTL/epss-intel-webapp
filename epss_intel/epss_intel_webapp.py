'''
EPSS Intel Web App: A web-based tool to fetch and analyze EPSS scores and CVE descriptions.
Original Author: Omar Santos @santosomar (for foundational concept and initial CLI version)
Version: 2.0.0
Refactored and Re-authored by: [Your Name Here] - Web App Integration
'''

import sys
import argparse
import requests
import re
import csv
import json
import time
import os
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import Bottle components
from bottle import route, run, template, request, static_file
import os
import bottle

# Set template path globally
bottle.TEMPLATE_PATH.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../views')))

# --- (Existing EPSS Intel classes will go here, adapted for web context) ---

@dataclass
class EPSSResult:
    cve: str
    epss: float = 0.0
    percentile: float = 0.0
    date: str = ""
    status: str = "success"  # "success", "not_found", "error"
    description: str = ""
    title: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: str = ""
    is_kev: bool = False
    error_message: Optional[str] = None

class CISAClient:
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_FILE = os.path.expanduser("~/.epss_cisa_kev.json")
    CACHE_EXPIRY = 86400  # 24 hours

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.kev_list = self._get_kev_list()

    def _get_kev_list(self) -> List[str]:
        if os.path.exists(self.CACHE_FILE):
            mtime = os.path.getmtime(self.CACHE_FILE)
            if time.time() - mtime < self.CACHE_EXPIRY:
                try:
                    with open(self.CACHE_FILE, 'r') as f:
                        data = json.load(f)
                        return [v["cveID"] for v in data.get("vulnerabilities", [])]
                except (json.JSONDecodeError, IOError):
                    pass
        
        try:
            # Removed verbose print for web app; consider proper logging
            response = requests.get(self.KEV_URL, timeout=30)
            response.raise_for_status()
            data = response.json()
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(data, f)
            return [v["cveID"] for v in data.get("vulnerabilities", [])]
        except Exception as e:
            # Proper logging for web app
            print(f"Error fetching CISA KEV list: {e}", file=sys.stderr) 
            if os.path.exists(self.CACHE_FILE):
                try:
                    with open(self.CACHE_FILE, 'r') as f:
                        data = json.load(f)
                        return [v["cveID"] for v in data.get("vulnerabilities", [])]
                except:
                    pass
            return []

    def is_on_kev(self, cve: str) -> bool:
        return cve.upper() in self.kev_list

class CveServicesClient:
    BASE_URL = "https://cveawg.mitre.org/api/cve"

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def fetch_details(self, cve: str) -> Dict:
        url = f"{self.BASE_URL}/{cve}"
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 404:
                return {}
            response.raise_for_status()
            data = response.json()
            
            details = {
                "title": "",
                "cvss_score": None,
                "cvss_severity": "",
                "description": ""
            }
            
            containers = data.get("containers", {})
            cna = containers.get("cna", {})
            
            details["title"] = cna.get("title", "")
            
            metrics = cna.get("metrics", [])
            for metric in metrics:
                for ver in ["cvssV3_1", "cvssV3_0"]:
                    if ver in metric:
                        m_data = metric[ver]
                        details["cvss_score"] = m_data.get("baseScore")
                        details["cvss_severity"] = m_data.get("baseSeverity", "").capitalize()
                        break
                if details["cvss_score"] is not None:
                    break
            
            descriptions = cna.get("descriptions", [])
            for d in descriptions:
                if d.get("lang") == "en":
                    details["description"] = d.get("value", "")
                    break
            if not details["description"] and descriptions:
                details["description"] = descriptions[0].get("value", "")
                
            return details
        except Exception as e:
            # Proper logging for web app
            print(f"Error fetching CVE details for {cve}: {e}", file=sys.stderr)
            return {}

class CVECache:
    CACHE_FILE = os.path.expanduser("~/.epss_cve_cache.json")

    def __init__(self):
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Dict]:
        if os.path.exists(self.CACHE_FILE):
            try:
                with open(self.CACHE_FILE, 'r') as f:
                    data = json.load(f)
                    if data and isinstance(next(iter(data.values())), str):
                        return {k: {"description": v} for k, v in data.items()}
                    return data
            except (json.JSONDecodeError, IOError, StopIteration):
                return {}
        return {}

    def save_cache(self):
        try:
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(self.cache, f, indent=4)
        except IOError:
            print(f"Error saving CVE cache to {self.CACHE_FILE}", file=sys.stderr)

    def get(self, cve: str) -> Optional[Dict]:
        return self.cache.get(cve.upper())

    def set(self, cve: str, details: Dict):
        if cve.upper() not in self.cache:
            self.cache[cve.upper()] = {}
        self.cache[cve.upper()].update(details)

class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose
        self.delay = 0.6 if api_key else 6.1 

    def fetch_description(self, cve: str) -> str:
        url = f"{self.BASE_URL}?cveId={cve}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 403:
                # Log rate limit, don't sleep in web context
                print(f"Rate limited by NVD API for {cve}.", file=sys.stderr)
                return "Error: NVD API rate limited."
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                cve_data = vulnerabilities[0].get('cve', {})
                desc_list = cve_data.get('descriptions', [])
                for d in desc_list:
                    if d.get('lang') == 'en':
                        return d.get('value', "")
                if desc_list:
                    return desc_list[0].get('value', "")
            
            return "No description found."
        except Exception as e:
            print(f"Error fetching NVD description for {cve}: {e}", file=sys.stderr)
            return f"Error: {str(e)}"

class EPSSAPIClient:
    BASE_URL = "https://api.first.org/data/v1/epss"
    URL_LIMIT = 2000

    def __init__(self, verbose=False):
        self.verbose = verbose

    def fetch_scores(self, cve_list: List[str]) -> List[EPSSResult]:
        results = []
        chunks = self._chunk_cves(cve_list)
        
        # Removed rich progress and verbose prints for web app
        for chunk in chunks:
            chunk_results = self._fetch_chunk(chunk)
            results.extend(chunk_results)
        
        return results

    def _chunk_cves(self, cve_list: List[str]) -> List[List[str]]:
        chunks = []
        current_chunk = []
        current_len = len(self.BASE_URL) + 5
        
        for cve in cve_list:
            if current_len + len(cve) + 1 > self.URL_LIMIT:
                chunks.append(current_chunk)
                current_chunk = []
                current_len = len(self.BASE_URL) + 5
            
            current_chunk.append(cve)
            current_len += len(cve) + 1
            
        if current_chunk:
            chunks.append(current_chunk)
        return chunks

    def _fetch_chunk(self, cve_chunk: List[str]) -> List[EPSSResult]:
        cves_param = ",".join(cve_chunk)
        url = f"{self.BASE_URL}?cve={cves_param}"
        
        retries = 3
        backoff = 1
        
        results_map = {cve: EPSSResult(cve=cve, status="not_found") for cve in cve_chunk}

        for attempt in range(retries):
            try:
                # Removed verbose print for web app
                response = requests.get(url, timeout=15)
                response.raise_for_status()
                data = response.json()
                
                if 'data' in data:
                    for item in data['data']:
                        cve_id = item.get('cve')
                        if cve_id in results_map:
                            results_map[cve_id] = EPSSResult(
                                cve=cve_id,
                                epss=float(item.get('epss', 0.0)),
                                percentile=float(item.get('percentile', 0.0)),
                                date=item.get('date', ""),
                                status="success"
                            )
                return list(results_map.values())

            except (requests.exceptions.RequestException, ValueError) as e:
                print(f"Error fetching chunk (Attempt {attempt + 1}/{retries}): {e}", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    for cve in cve_chunk:
                        results_map[cve].status = "error"
                        results_map[cve].error_message = str(e)
        
        return list(results_map.values())


def validate_cve(cve: str) -> bool:
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', cve, re.IGNORECASE))

# --- Web App Specific Logic ---

@route('/')
@route('/epss')
def index_form():
    """
    Displays the CVE input form.
    """
    return template('index', results=None, error=None)

@route('/epss', method='POST')
def process_cves():
    """
    Processes CVE input from the form, fetches data, and displays results.
    """
    cve_input = request.forms.get('cve_input', '').strip()
    cve_file = request.files.get('cve_file')
    
    cve_list = []
    if cve_input:
        cve_list.extend([c.strip() for c in cve_input.split(',') if c.strip()])
    
    if cve_file and cve_file.file:
        for line in cve_file.file:
            decoded_line = line.decode('utf-8').strip()
            if decoded_line:
                cve_list.append(decoded_line)

    if not cve_list:
        return template('index', results=None, error="Please provide at least one CVE ID.")

    valid_cves = []
    invalid_cves = []
    for c in cve_list:
        if validate_cve(c):
            valid_cves.append(c.upper())
        else:
            invalid_cves.append(c)

    if invalid_cves:
        error_msg = f"Warning: Skipping {len(invalid_cves)} invalid CVE formats: {', '.join(invalid_cves)}"
        # For a web app, we might display this warning on the page rather than stdout
        print(error_msg, file=sys.stderr) # Log to stderr

    if not valid_cves:
        return template('index', results=None, error=error_msg)

    # --- Core Logic from original main() function, adapted for web ---
    client = EPSSAPIClient() # verbose=False for web app
    results = client.fetch_scores(valid_cves)

    cisa = CISAClient() # verbose=False
    for res in results:
        res.is_kev = cisa.is_on_kev(res.cve)

    cache = CVECache()
    cve_svc = CveServicesClient() # verbose=False
    to_fetch_metadata = [res for res in results if res.status == "success" and (not cache.get(res.cve) or "cvss_score" not in cache.get(res.cve))]
    
    def fetch_metadata_for_web(res):
        cached_data = cache.get(res.cve)
        if cached_data and "cvss_score" in cached_data:
            return res.cve, cached_data
        details = cve_svc.fetch_details(res.cve)
        if details:
            cache.set(res.cve, details)
        return res.cve, details

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_metadata_for_web, res): res for res in to_fetch_metadata}
        for future in as_completed(futures):
            cve_id, details = future.result()
            res = next(r for r in results if r.cve == cve_id) # Find the original result object
            res.title = details.get("title", "")
            res.cvss_score = details.get("cvss_score")
            res.cvss_severity = details.get("cvss_severity", "")
            if not res.description:
                res.description = details.get("description", "")
    cache.save_cache()

    # NVD descriptions (optional, could be a checkbox in form)
    # For now, let's assume descriptions are primarily from CVE Services
    # if not res.description, then use NVD if available
    nvd_client = NVDClient() # verbose=False, api_key=None initially
    to_fetch_nvd_desc = [res for res in results if res.status == "success" and not res.description]
    if to_fetch_nvd_desc:
        with ThreadPoolExecutor(max_workers=5) as executor: # Fewer workers for NVD rate limit
            futures_map = {executor.submit(nvd_client.fetch_description, res.cve): res for res in to_fetch_nvd_desc}
            for future in as_completed(futures_map):
                desc = future.result()
                original_res = futures_map[future] # Get the original EPSSResult object
                original_res.description = desc
                cache.set(original_res.cve, {"description": desc}) # Update cache
        cache.save_cache()

    # Filtering (from form fields, if implemented)
    # For now, no filtering applied, show all valid results
    
    # Sorting (from form fields, if implemented)
    results.sort(key=lambda x: x.epss, reverse=True) # Default sort by EPSS

    return template('index', results=results, error=None)

# Static files for CSS/JS
@route('/static/<filename:path>')
def send_static(filename):
    return static_file(filename, root=os.path.join(os.path.dirname(__file__), '../../static/'))

if __name__ == '__main__':
    # Ensure 'views' directory exists for templates
    if not os.path.exists('views'):
        os.makedirs('views')
    # Ensure 'static' directory exists for static assets like CSS
    if not os.path.exists('static'):
        os.makedirs('static')
        
    run(host='localhost', port=8080, debug=True, reloader=True, template_lookup=[os.path.join(os.path.dirname(__file__), '../../views/')])
