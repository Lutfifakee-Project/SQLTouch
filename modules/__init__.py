"""
SQLTouch Modules
Advanced SQL Injection Tool
"""

__version__ = "2.0.0"
__author__ = "SQLTouch Team"

from .core import SQLTouchCore
from .detector import SQLDetector
from .extractor import DataExtractor
from .utils import banner, simple_banner, Color, get_random_agent, get_os_info, save_results

__all__ = [
    'SQLTouchCore', 
    'SQLDetector', 
    'DataExtractor', 
    'banner', 
    'simple_banner',
    'Color', 
    'get_random_agent', 
    'get_os_info',
    'save_results'
]