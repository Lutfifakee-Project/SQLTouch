"""
Utility functions for SQLTouch
"""

import sys
import random
import string
import platform
from colorama import Fore, Style

VERSION = "2.0.0"

class Color:
    """Color codes for output - Windows & Linux compatible"""
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

def banner(version=VERSION):
    """Return cool ASCII art banner"""
    banner_text = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.WHITE}                                                                                      {Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}    ███████╗ ██████╗ ██╗     ████████╗ ██████╗ ██╗   ██╗ ██████╗██╗  ██╗{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}    ██╔════╝██╔═══██╗██║     ╚══██╔══╝██╔═══██╗██║   ██║██╔════╝██║  ██║{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}    ███████╗██║   ██║██║        ██║   ██║   ██║██║   ██║██║     ███████║{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}    ╚════██║██║▄▄ ██║██║        ██║   ██║   ██║██║   ██║██║     ██╔══██║{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}    ███████║╚██████╔╝███████╗   ██║   ╚██████╔╝╚██████╔╝╚██████╗██║  ██║{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}    ╚══════╝ ╚══▀▀═╝ ╚══════╝   ╚═╝    ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝{Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}                                                                                      {Fore.CYAN}║
{Fore.CYAN}║{Fore.YELLOW}                         SQL INJECTION AUTOMATION TOOL v{version}                          {Fore.CYAN}║
{Fore.CYAN}║{Fore.MAGENTA}                    Advanced Detection | Automatic Extraction | WAF Bypass              {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}                                                                                      {Fore.CYAN}║
{Fore.CYAN}║{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.CYAN}                             GitHub: https://github.com/lutfifakeexone/SQLTouch                            {Style.RESET_ALL}
"""
    return banner_text

def simple_banner(version=VERSION):
    """Return simple banner for smaller terminals"""
    banner_text = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.GREEN}   ███████╗ ██████╗ ██╗     ████████╗ ██████╗ ██╗   ██╗{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}   ██╔════╝██╔═══██╗██║     ╚══██╔══╝██╔═══██╗██║   ██║{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}   ███████╗██║   ██║██║        ██║   ██║   ██║██║   ██║{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}   ╚════██║██║▄▄ ██║██║        ██║   ██║   ██║██║   ██║{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}   ███████║╚██████╔╝███████╗   ██║   ╚██████╔╝╚██████╔╝{Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}   ╚══════╝ ╚══▀▀═╝ ╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ {Fore.CYAN}║
{Fore.CYAN}║{Fore.YELLOW}               SQL Injection Tool v{version}                    {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.CYAN}         GitHub: https://github.com/lutfifakeexone/SQLTouch{Style.RESET_ALL}
"""
    return banner_text

def get_random_agent():
    """Return random User-Agent"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
    ]
    return random.choice(user_agents)

def get_os_info():
    """Return OS information"""
    return f"{platform.system()} {platform.release()}"

def save_results(filename, data):
    """Save results to file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            if filename.endswith('.json'):
                import json
                json.dump(data, f, indent=2)
            else:
                f.write(str(data))
        return True
    except Exception as e:
        print(f"{Color.RED}[-] Failed to save: {e}{Color.RESET}")
        return False