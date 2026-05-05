'''
EPSS Intel: A powerful CLI tool to fetch and analyze EPSS scores and CVE descriptions.
Author: Omar Santos @santosomar
Version: 1.2
Enhanced by: Forge (Gemini CLI Engineer)
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

# Try to import rich for enhanced output, fallback to standard formatting if not available
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import track, Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

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
    """
    Client for fetching the CISA Known Exploited Vulnerabilities (KEV) list.
    """
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
        
        # Cache expired or missing, fetch fresh list
        try:
            if self.verbose: print("\nFetching fresh CISA KEV list...")
            response = requests.get(self.KEV_URL, timeout=30)
            response.raise_for_status()
            data = response.json()
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(data, f)
            return [v["cveID"] for v in data.get("vulnerabilities", [])]
        except Exception as e:
            if self.verbose: print(f"Error fetching CISA KEV list: {e}")
            # Fallback to expired cache if available
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
    """
    Client for fetching rich CVE metadata from the CVE Services API (v5).
    """
    BASE_URL = "https://cveawg.mitre.org/api/cve"

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def fetch_details(self, cve: str) -> Dict:
        """
        Fetches title, CVSS score, and severity from CVE Services.
        """
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
            
            # Navigate CVE JSON v5 structure
            containers = data.get("containers", {})
            cna = containers.get("cna", {})
            
            # Title
            details["title"] = cna.get("title", "")
            
            # Metrics (CVSS)
            metrics = cna.get("metrics", [])
            for metric in metrics:
                # Prefer CVSS v3.1, then v3.0
                for ver in ["cvssV3_1", "cvssV3_0"]:
                    if ver in metric:
                        m_data = metric[ver]
                        details["cvss_score"] = m_data.get("baseScore")
                        details["cvss_severity"] = m_data.get("baseSeverity", "").capitalize()
                        break
                if details["cvss_score"] is not None:
                    break
            
            # Description
            descriptions = cna.get("descriptions", [])
            for d in descriptions:
                if d.get("lang") == "en":
                    details["description"] = d.get("value", "")
                    break
            if not details["description"] and descriptions:
                details["description"] = descriptions[0].get("value", "")
                
            return details
        except Exception as e:
            if self.verbose:
                print(f"\nError fetching CVE details for {cve}: {e}")
            return {}

class CVECache:
    """
    Handles local caching of CVE metadata to reduce API calls and improve performance.
    """
    CACHE_FILE = os.path.expanduser("~/.epss_cve_cache.json")

    def __init__(self):
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Dict]:
        if os.path.exists(self.CACHE_FILE):
            try:
                with open(self.CACHE_FILE, 'r') as f:
                    data = json.load(f)
                    # Support legacy string-only cache
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
            pass

    def get(self, cve: str) -> Optional[Dict]:
        return self.cache.get(cve.upper())

    def set(self, cve: str, details: Dict):
        # Update existing entry or create new one
        if cve.upper() not in self.cache:
            self.cache[cve.upper()] = {}
        self.cache[cve.upper()].update(details)

class NVDClient:
    """
    Client for fetching CVE descriptions from the NIST NVD API.
    """
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose
        # NVD rate limits: 5 requests per 30s without key (~6s delay), 50 per 30s with key (~0.6s delay).
        self.delay = 0.6 if api_key else 6.1 

    def fetch_description(self, cve: str) -> str:
        url = f"{self.BASE_URL}?cveId={cve}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 403: # Rate limited
                if self.verbose: print(f"\nRate limited by NVD API for {cve}. Waiting 30s...")
                time.sleep(30)
                return self.fetch_description(cve)
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                cve_data = vulnerabilities[0].get('cve', {})
                desc_list = cve_data.get('descriptions', [])
                # Prefer English description
                for d in desc_list:
                    if d.get('lang') == 'en':
                        return d.get('value', "")
                if desc_list:
                    return desc_list[0].get('value', "")
            
            return "No description found."
        except Exception as e:
            if self.verbose: print(f"\nError fetching NVD description for {cve}: {e}")
            return f"Error: {str(e)}"

class EPSSAPIClient:
    BASE_URL = "https://api.first.org/data/v1/epss"
    URL_LIMIT = 2000

    def __init__(self, verbose=False):
        self.verbose = verbose

    def fetch_scores(self, cve_list: List[str]) -> List[EPSSResult]:
        """
        Fetches EPSS scores for a list of CVE IDs, handling batching to stay within URL limits.
        """
        results = []
        chunks = self._chunk_cves(cve_list)
        
        if RICH_AVAILABLE:
            # Use rich progress tracking if available
            iterator = track(chunks, description="Fetching EPSS scores...")
        else:
            iterator = chunks
            if self.verbose:
                print(f"Fetching {len(cve_list)} CVEs in {len(chunks)} chunks...")

        for chunk in iterator:
            chunk_results = self._fetch_chunk(chunk)
            results.extend(chunk_results)
        
        return results

    def _chunk_cves(self, cve_list: List[str]) -> List[List[str]]:
        """
        Splits CVE list into chunks to ensure URL length remains under the 2,000 char limit.
        """
        chunks = []
        current_chunk = []
        current_len = len(self.BASE_URL) + 5 # Base URL plus ?cve=
        
        for cve in cve_list:
            # +1 for comma separator
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
        """
        Fetches a single chunk of CVEs from the API.
        """
        cves_param = ",".join(cve_chunk)
        url = f"{self.BASE_URL}?cve={cves_param}"
        
        retries = 3
        backoff = 1
        
        # Pre-populate results with "not_found"
        results_map = {cve: EPSSResult(cve=cve, status="not_found") for cve in cve_chunk}

        for attempt in range(retries):
            try:
                if self.verbose:
                    print(f"Requesting: {url}")
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
                if self.verbose:
                    print(f"Error fetching chunk (Attempt {attempt + 1}/{retries}): {e}")
                if attempt < retries - 1:
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    # Mark chunk as error after final retry
                    for cve in cve_chunk:
                        results_map[cve].status = "error"
                        results_map[cve].error_message = str(e)
        
        return list(results_map.values())

class Formatter:
    """
    Handles different output formats for EPSS results.
    """
    @staticmethod
    def get_color(epss: float) -> str:
        if epss > 0.1: return "red"
        if epss > 0.01: return "yellow"
        return "green"

    @staticmethod
    def print_table(results: List[EPSSResult], show_desc: bool = False, show_details: bool = False):
        if RICH_AVAILABLE:
            console = Console()
            table = Table(title="EPSS Scores & Vulnerability Details")
            table.add_column("CVE", style="cyan", no_wrap=True)
            table.add_column("KEV", justify="center")
            if show_details:
                table.add_column("Title", justify="left", overflow="fold")
                table.add_column("CVSS", justify="center")
                table.add_column("Severity", justify="center")
            table.add_column("EPSS Score (30d Prob)", justify="right")
            table.add_column("Percentile (Relative Rank)", justify="right")
            if show_desc:
                table.add_column("Description", justify="left", overflow="fold")
            table.add_column("Date", justify="center")
            table.add_column("Status")

            for res in results:
                color = Formatter.get_color(res.epss) if res.status == "success" else "white"
                kev_status = "[bold red]YES[/bold red]" if res.is_kev else "no"
                row = [res.cve, kev_status]
                
                if show_details:
                    row.append(res.title or "-")
                    row.append(f"{res.cvss_score:.1f}" if res.cvss_score is not None else "-")
                    row.append(res.cvss_severity or "-")
                
                row.extend([
                    f"[{color}]{res.epss:.5f}[/{color}]" if res.status == "success" else "-",
                    f"{res.percentile:.5f}" if res.status == "success" else "-",
                ])
                if show_desc:
                    row.append(res.description or "-")
                row.extend([
                    res.date or "-",
                    res.status if res.status == "success" else f"[red]{res.status}[/red]"
                ])
                table.add_row(*row)
            
            console.print(table)
            
            # Add Legend block
            console.print("\n[bold]Legend:[/bold]")
            console.print("[bold red]KEV:[/bold red] CVE is on the CISA Known Exploited Vulnerabilities list (Active exploitation!).")
            console.print("[cyan]EPSS Score (30d Prob):[/cyan] The probability (0.0 to 1.0) of this CVE being exploited in the next 30 days.")
            console.print("[cyan]Percentile (Relative Rank):[/cyan] The risk ranking of this CVE compared to all other known vulnerabilities.")
            if show_details:
                console.print("[cyan]CVSS Score:[/cyan] The Common Vulnerability Scoring System v3.x base score.")
        else:
            # Fallback to standard string formatting
            header = f"{'CVE':<20} {'KEV':<5}"
            if show_details:
                header += f" {'Title':<30} {'CVSS':<6} {'Severity':<10}"
            header += f" {'EPSS Score':<15} {'Percentile':<15}"
            if show_desc:
                header += f" {'Description':<50}"
            header += f" {'Date':<12} {'Status'}"
            
            print(f"\n{header}")
            print("-" * (len(header) + 5))
            
            for res in results:
                kev_str = "YES" if res.is_kev else "no"
                row = f"{res.cve:<20} {kev_str:<5}"
                if show_details:
                    title = (res.title[:27] + "...") if len(res.title) > 27 else res.title
                    cvss = f"{res.cvss_score:.1f}" if res.cvss_score is not None else "-"
                    row += f" {title:<30} {cvss:<6} {res.cvss_severity or '-':<10}"
                
                epss_str = f"{res.epss:.5f}" if res.status == "success" else "-"
                perc_str = f"{res.percentile:.5f}" if res.status == "success" else "-"
                date_str = res.date if res.status == "success" else "-"
                row += f" {epss_str:<15} {perc_str:<15}"
                
                if show_desc:
                    desc = (res.description[:47] + "...") if len(res.description) > 47 else res.description
                    row += f" {desc:<50}"
                row += f" {date_str:<12} {res.status}"
                print(row)

    @staticmethod
    def write_csv(results: List[EPSSResult], output_file: str):
        with open(output_file, mode='w', newline='') as f:
            fieldnames = ["cve", "is_kev", "epss", "percentile", "date", "status", "description", "title", "cvss_score", "cvss_severity", "error_message"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for res in results:
                writer.writerow(asdict(res))

    @staticmethod
    def write_json(results: List[EPSSResult], output_file: str):
        with open(output_file, mode='w') as f:
            json.dump([asdict(res) for res in results], f, indent=4)

    @staticmethod
    def print_summary(results: List[EPSSResult]):
        total = len(results)
        success = [r for r in results if r.status == "success"]
        kev_count = sum(1 for r in success if r.is_kev)
        avg_epss = sum(r.epss for r in success) / len(success) if success else 0
        
        severity_counts = {}
        for r in success:
            sev = r.cvss_severity or "Unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if RICH_AVAILABLE:
            console = Console()
            console.print("\n[bold]Summary Report[/bold]")
            console.print(f"Total CVEs analyzed: {total}")
            console.print(f"Successfully fetched: {len(success)}")
            console.print(f"Actively exploited (KEV): [bold red]{kev_count}[/bold red]")
            console.print(f"Average EPSS Score: {avg_epss:.5f}")
            
            if severity_counts:
                console.print("\n[bold]Severity Breakdown:[/bold]")
                for sev, count in sorted(severity_counts.items()):
                    console.print(f" - {sev}: {count}")
        else:
            print("\nSummary Report")
            print(f"Total CVEs analyzed: {total}")
            print(f"Successfully fetched: {len(success)}")
            print(f"Actively exploited (KEV): {kev_count}")
            print(f"Average EPSS Score: {avg_epss:.5f}")
            if severity_counts:
                print("\nSeverity Breakdown:")
                for sev, count in sorted(severity_counts.items()):
                    print(f" - {sev}: {count}")

def validate_cve(cve: str) -> bool:
    """
    Validates the format of a CVE ID using regex.
    """
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', cve, re.IGNORECASE))

def main():
    parser = argparse.ArgumentParser(
        description="EPSS Intel: Fetch and analyze EPSS scores and CVE descriptions.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Positioning argument for backward compatibility
    parser.add_argument('cve', nargs='?', help='Single CVE identifier to query (e.g., CVE-2021-44228)')
    
    # New batch input options
    parser.add_argument('-l', '--list', help='Comma-separated list of CVE identifiers')
    parser.add_argument('-f', '--file', help='Path to a file containing newline-separated CVE identifiers')
    
    # Output options
    parser.add_argument('-o', '--output', help='Path to save results')
    parser.add_argument('--format', choices=['table', 'csv', 'json'], default='table', help='Output format (default: table)')
    
    # CVE Services options (Rich metadata)
    parser.add_argument('-d', '--cve-details', action='store_true', help='Include rich metadata (Title, CVSS, Severity, Description) from CVE Services')

    # Filtering and Sorting options
    parser.add_argument('--min-epss', type=float, help='Filter results by minimum EPSS score')
    parser.add_argument('--min-cvss', type=float, help='Filter results by minimum CVSS score')
    parser.add_argument('--sort', choices=['epss', 'cvss', 'cve'], help='Sort results by field')
    parser.add_argument('--kev-only', action='store_true', help='Only show vulnerabilities on CISA KEV list')
    parser.add_argument('--no-summary', action='store_true', help='Disable summary statistics')

    # NVD Description options (Fallback/Specific NVD)
    parser.add_argument('--include-desc', action='store_true', help='Include vulnerability descriptions specifically from NVD (slow)')
    parser.add_argument('--nvd-key', help='NVD API key (increases rate limit)')

    # Display/Logging options
    parser.add_argument('-s', '--silent', action='store_true', help='Legacy mode: print only the raw score for a single CVE')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging and debug information')

    args = parser.parse_args()

    # Collect CVEs from all input sources
    cve_list = []
    if args.cve:
        cve_list.append(args.cve)
    if args.list:
        cve_list.extend([c.strip() for c in args.list.split(',')])
    if args.file:
        try:
            with open(args.file, 'r') as f:
                cve_list.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"Error reading file {args.file}: {e}")
            sys.exit(1)

    # Show help if no input is provided
    if not cve_list:
        parser.print_help()
        sys.exit(0)

    # Validate CVE formats
    valid_cves = []
    invalid_cves = []
    for c in cve_list:
        if validate_cve(c):
            valid_cves.append(c.upper())
        else:
            invalid_cves.append(c)

    if invalid_cves and args.verbose:
        print(f"Warning: Skipping {len(invalid_cves)} invalid CVE formats: {', '.join(invalid_cves)}")

    if not valid_cves:
        print("Error: No valid CVE identifiers provided.")
        sys.exit(1)

    # Fetch EPSS data
    client = EPSSAPIClient(verbose=args.verbose)
    results = client.fetch_scores(valid_cves)

    # Check CISA KEV status for all results
    cisa = CISAClient(verbose=args.verbose)
    for res in results:
        res.is_kev = cisa.is_on_kev(res.cve)

    # Fetch CVE Details (Title, CVSS, Severity) if requested (Parallelized)
    cache = CVECache()
    if args.cve_details:
        cve_svc = CveServicesClient(verbose=args.verbose)
        to_fetch = [res for res in results if res.status == "success"]
        
        def fetch_metadata(res):
            cached_data = cache.get(res.cve)
            if cached_data and "cvss_score" in cached_data:
                return res.cve, cached_data
            details = cve_svc.fetch_details(res.cve)
            if details:
                cache.set(res.cve, details)
            return res.cve, details

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=Console()
            ) as progress:
                task = progress.add_task("Fetching CVE metadata...", total=len(to_fetch))
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {executor.submit(fetch_metadata, res): res for res in to_fetch}
                    for future in as_completed(futures):
                        cve_id, details = future.result()
                        res = next(r for r in to_fetch if r.cve == cve_id)
                        res.title = details.get("title", "")
                        res.cvss_score = details.get("cvss_score")
                        res.cvss_severity = details.get("cvss_severity", "")
                        if not res.description:
                            res.description = details.get("description", "")
                        progress.update(task, advance=1)
        else:
            if args.verbose: print(f"Fetching metadata for {len(to_fetch)} CVEs...")
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(fetch_metadata, res): res for res in to_fetch}
                for future in as_completed(futures):
                    cve_id, details = future.result()
                    res = next(r for r in to_fetch if r.cve == cve_id)
                    res.title = details.get("title", "")
                    res.cvss_score = details.get("cvss_score")
                    res.cvss_severity = details.get("cvss_severity", "")
                    if not res.description:
                        res.description = details.get("description", "")
        
        cache.save_cache()

    # Fetch Descriptions from NVD if requested and not already found
    if args.include_desc:
        nvd = NVDClient(api_key=args.nvd_key, verbose=args.verbose)
        to_fetch = [res for res in results if res.status == "success" and not res.description]
        to_fetch_final = []
        for res in to_fetch:
            cached_data = cache.get(res.cve)
            if cached_data and cached_data.get("description"):
                res.description = cached_data["description"]
            else:
                to_fetch_final.append(res)
        
        if to_fetch_final:
            def fetch_nvd(res):
                desc = nvd.fetch_description(res.cve)
                cache.set(res.cve, {"description": desc})
                return res.cve, desc

            if RICH_AVAILABLE:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), 
                             BarColumn(), TaskProgressColumn(), console=Console()) as progress:
                    task = progress.add_task("Fetching NVD descriptions...", total=len(to_fetch_final))
                    # NVD is rate-limited, so we use fewer workers and add delay if no key
                    workers = 5 if args.nvd_key else 1
                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        for res in to_fetch_final:
                            desc = nvd.fetch_description(res.cve)
                            res.description = desc
                            cache.set(res.cve, {"description": desc})
                            progress.update(task, advance=1)
                            if not args.nvd_key: time.sleep(nvd.delay)
            else:
                if args.verbose: print(f"Fetching {len(to_fetch_final)} descriptions from NVD...")
                for res in to_fetch_final:
                    desc = nvd.fetch_description(res.cve)
                    res.description = desc
                    cache.set(res.cve, {"description": desc})
                    if not args.nvd_key: time.sleep(nvd.delay)
            
            cache.save_cache()

    # Filtering
    if args.min_epss is not None:
        results = [r for r in results if r.epss >= args.min_epss]
    if args.min_cvss is not None:
        results = [r for r in results if r.cvss_score is not None and r.cvss_score >= args.min_cvss]
    if args.kev_only:
        results = [r for r in results if r.is_kev]

    # Sorting
    if args.sort == 'epss':
        results.sort(key=lambda x: x.epss, reverse=True)
    elif args.sort == 'cvss':
        results.sort(key=lambda x: x.cvss_score or 0, reverse=True)
    elif args.sort == 'cve':
        results.sort(key=lambda x: x.cve)

    # Support legacy --silent mode for single CVE lookups
    if args.silent and len(valid_cves) == 1:
        res = results[0]
        if res.status == "success":
            print(res.epss)
        else:
            print(f"Error: {res.error_message or res.status}")
        return

    # Determine output format and destination
    if args.output:
        fmt = args.format
        if not args.format or args.format == 'table':
            if args.output.endswith('.csv'): fmt = 'csv'
            elif args.output.endswith('.json'): fmt = 'json'

        if fmt == 'csv':
            Formatter.write_csv(results, args.output)
            print(f"Results successfully saved to {args.output}")
        elif fmt == 'json':
            Formatter.write_json(results, args.output)
            print(f"Results successfully saved to {args.output}")
        else:
            Formatter.print_table(results, show_desc=args.include_desc or args.cve_details, show_details=args.cve_details)
    else:
        Formatter.print_table(results, show_desc=args.include_desc or args.cve_details, show_details=args.cve_details)

    # Print Summary Statistics
    if not args.no_summary and not args.silent:
        Formatter.print_summary(results)

if __name__ == "__main__":
    main()
