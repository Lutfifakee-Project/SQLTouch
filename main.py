#!/usr/bin/env python3
"""
SQLTouch - Advanced SQL Injection Tool
Version: 2.0.0
Author: SQLTouch Team
GitHub: https://github.com/Lutfifakee-Project/SQLTouch
"""

import sys
import os
import argparse
from colorama import init, Fore, Style
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.core import SQLTouchCore
from modules.utils import banner, simple_banner, Color, get_os_info

init(autoreset=True)

VERSION = "2.0.0"

def get_terminal_width():
    """Get terminal width"""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except:
        return 80

def main():
    """Main entry point"""
    # Check terminal width for banner selection
    width = get_terminal_width()
    
    # Print banner
    if width >= 100:
        print(banner(VERSION))
    else:
        print(simple_banner(VERSION))
    
    parser = argparse.ArgumentParser(
        description='SQLTouch - Advanced SQL Injection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}Examples:
  python main.py -u "http://example.com/page.php?id=1"
  python main.py -u "http://example.com/page.php?id=1" -v --techniques BET
  python main.py -u "http://example.com/page.php?id=1" --proxy "http://127.0.0.1:8080"
  python main.py -u "http://example.com/page.php?id=1" --random-agent --delay 1
  python main.py -f targets.txt -t 10 --level 3
        {Style.RESET_ALL}
        """
    )
    
    # Target options
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-u', '--url', help='Target URL (e.g., "http://site.com/page.php?id=1")')
    target_group.add_argument('-f', '--file', help='File containing list of URLs')
    target_group.add_argument('--data', help='POST data (e.g., "user=admin&pass=123")')
    target_group.add_argument('--cookie', help='HTTP Cookie header')
    target_group.add_argument('-H', '--header', action='append', help='Extra headers (e.g., "X-Forwarded-For:127.0.0.1")')
    
    # Request options
    request_group = parser.add_argument_group('Request')
    request_group.add_argument('--proxy', help='Use proxy (e.g., "http://127.0.0.1:8080")')
    request_group.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    request_group.add_argument('--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    request_group.add_argument('--delay', type=float, default=0, help='Delay between requests (seconds)')
    request_group.add_argument('--random-agent', action='store_true', help='Use random User-Agent')
    
    # Detection options
    detection_group = parser.add_argument_group('Detection')
    detection_group.add_argument('--level', type=int, choices=[1,2,3,4,5], default=1, 
                                help='Level of tests (1-5, default: 1)')
    detection_group.add_argument('--risk', type=int, choices=[1,2,3], default=1, 
                                help='Risk of tests (1-3, default: 1)')
    detection_group.add_argument('--techniques', default='BETU', 
                                help='Techniques: B:Boolean, E:Error, U:Union, T:Time (default: BETU)')
    detection_group.add_argument('--skip-waf', action='store_true', help='Skip WAF detection')
    
    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    output_group.add_argument('--output', help='Save results to file')
    output_group.add_argument('--json', action='store_true', help='Output in JSON format')
    
    # Extraction options
    extract_group = parser.add_argument_group('Extraction')
    extract_group.add_argument('--dump', action='store_true', help='Dump database data')
    extract_group.add_argument('--db', help='Target database name')
    extract_group.add_argument('--table', help='Target table name')
    extract_group.add_argument('--columns', help='Target columns (comma separated)')
    
    args = parser.parse_args()
    
    # Check if target specified
    if not args.url and not args.file:
        print(f"{Color.RED}[-] No target specified!{Color.RESET}")
        print(f"{Color.YELLOW}[!] Use -u for single URL or -f for file list{Color.RESET}")
        parser.print_help()
        sys.exit(1)
    
    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                key, value = h.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Parse techniques
    techniques = [t.upper() for t in args.techniques if t.upper() in ['B', 'E', 'U', 'T']]
    if not techniques:
        techniques = ['B', 'E', 'U', 'T']
    
    # Create tool instance
    tool = SQLTouchCore(
        url=args.url,
        file_list=args.file,
        post_data=args.data,
        cookie=args.cookie,
        headers=headers,
        threads=args.threads,
        timeout=args.timeout,
        level=args.level,
        risk=args.risk,
        verbose=args.verbose,
        proxy=args.proxy,
        random_agent=args.random_agent,
        delay=args.delay,
        techniques=techniques,
        skip_waf=args.skip_waf,
        output_file=args.output,
        json_output=args.json,
        dump_data=args.dump,
        target_db=args.db,
        target_table=args.table,
        target_columns=args.columns
    )
    
    try:
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}[!] Interrupted by user{Color.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Color.RED}[-] Error: {e}{Color.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()