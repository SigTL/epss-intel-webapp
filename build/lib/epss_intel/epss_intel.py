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
    error_message: Optional[str] = None

class NVDCache:
    """
    Handles local caching of CVE descriptions to reduce API calls and improve performance.
    """
    CACHE_FILE = os.path.expanduser("~/.epss_nvd_cache.json")

    def __init__(self):
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict[str, str]:
        if os.path.exists(self.CACHE_FILE):
            try:
                with open(self.CACHE_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def save_cache(self):
        try:
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(self.cache, f, indent=4)
        except IOError:
            pass

    def get(self, cve: str) -> Optional[str]:
        return self.cache.get(cve.upper())

    def set(self, cve: str, description: str):
        self.cache[cve.upper()] = description

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
    def print_table(results: List[EPSSResult], show_desc: bool = False):
        if RICH_AVAILABLE:
            console = Console()
            table = Table(title="EPSS Scores")
            table.add_column("CVE", style="cyan", no_wrap=True)
            table.add_column("EPSS Score (30d Prob)", justify="right")
            table.add_column("Percentile (Relative Rank)", justify="right")
            if show_desc:
                table.add_column("Description", justify="left", overflow="fold")
            table.add_column("Date", justify="center")
            table.add_column("Status")

            for res in results:
                color = Formatter.get_color(res.epss) if res.status == "success" else "white"
                row = [
                    res.cve,
                    f"[{color}]{res.epss:.5f}[/{color}]" if res.status == "success" else "-",
                    f"{res.percentile:.5f}" if res.status == "success" else "-",
                ]
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
            console.print("[cyan]EPSS Score (30d Prob):[/cyan] The probability (0.0 to 1.0) of this CVE being exploited in the next 30 days.")
            console.print("[cyan]Percentile (Relative Rank):[/cyan] The risk ranking of this CVE compared to all other known vulnerabilities.")
        else:
            # Fallback to standard string formatting
            header = f"{'CVE':<20} {'EPSS Score (30d Prob)':<25} {'Percentile (Relative Rank)':<30}"
            if show_desc:
                header += f" {'Description':<50}"
            header += f" {'Date':<12} {'Status'}"
            
            print(f"\n{header}")
            print("-" * (len(header) + 10))
            
            for res in results:
                epss_str = f"{res.epss:.5f}" if res.status == "success" else "-"
                perc_str = f"{res.percentile:.5f}" if res.status == "success" else "-"
                date_str = res.date if res.status == "success" else "-"
                row = f"{res.cve:<20} {epss_str:<25} {perc_str:<30}"
                if show_desc:
                    desc = (res.description[:47] + "...") if len(res.description) > 47 else res.description
                    row += f" {desc:<50}"
                row += f" {date_str:<12} {res.status}"
                print(row)
            
            # Add Legend block for fallback
            print("\nLegend:")
            print("EPSS Score (30d Prob): The probability (0.0 to 1.0) of this CVE being exploited in the next 30 days.")
            print("Percentile (Relative Rank): The risk ranking of this CVE compared to all other known vulnerabilities.")

    @staticmethod
    def write_csv(results: List[EPSSResult], output_file: str):
        with open(output_file, mode='w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["cve", "epss", "percentile", "date", "status", "description", "error_message"])
            writer.writeheader()
            for res in results:
                writer.writerow(asdict(res))

    @staticmethod
    def write_json(results: List[EPSSResult], output_file: str):
        with open(output_file, mode='w') as f:
            json.dump([asdict(res) for res in results], f, indent=4)

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
    
    # NVD Description options
    parser.add_argument('-d', '--include-desc', action='store_true', help='Include vulnerability descriptions from NVD (slow)')
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

    # Fetch Descriptions if requested
    if args.include_desc:
        cache = NVDCache()
        nvd = NVDClient(api_key=args.nvd_key, verbose=args.verbose)
        
        to_fetch = [res for res in results if res.status == "success" and not cache.get(res.cve)]
        
        if to_fetch:
            if RICH_AVAILABLE:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=Console()
                ) as progress:
                    task = progress.add_task("Fetching NVD descriptions...", total=len(to_fetch))
                    for res in to_fetch:
                        desc = nvd.fetch_description(res.cve)
                        cache.set(res.cve, desc)
                        progress.update(task, advance=1)
                        # Without key, we must wait 6s between requests to avoid 403s
                        if not args.nvd_key and to_fetch.index(res) < len(to_fetch) - 1:
                            time.sleep(nvd.delay)
            else:
                if args.verbose: print(f"Fetching {len(to_fetch)} descriptions from NVD...")
                for res in to_fetch:
                    desc = nvd.fetch_description(res.cve)
                    cache.set(res.cve, desc)
                    if not args.nvd_key and to_fetch.index(res) < len(to_fetch) - 1:
                        time.sleep(nvd.delay)
            
            cache.save_cache()

        # Update results with cached/fetched descriptions
        for res in results:
            res.description = cache.get(res.cve) or ""

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
        # Auto-detect format from extension if output path is provided
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
            # Table output always goes to terminal
            Formatter.print_table(results, show_desc=args.include_desc)
    else:
        # Default to printing the table to terminal
        Formatter.print_table(results, show_desc=args.include_desc)

if __name__ == "__main__":
    main()
