"""
PhoneGuard Pro - Mobile Security & Maintenance System
======================================================
A comprehensive Python security tool that:
- Scans for malicious background processes
- Detects suspicious/unknown files
- Monitors system resources
- Cleans junk/cache
- Provides real-time threat detection

Compatible with Android (Termux), Linux, and Windows.
Install requirements: pip install psutil colorama requests hashlib
"""

import os
import sys
import time
import json
import hashlib
import platform
import threading
import subprocess
from datetime import datetime
from pathlib import Path

# ── Try importing optional libraries ─────────────────────────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[!] psutil not found. Run: pip install psutil")

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORAMA = True
except ImportError:
    COLORAMA = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ── Color helpers ─────────────────────────────────────────────────────────────
def red(t):    return (Fore.RED + t + Style.RESET_ALL) if COLORAMA else t
def green(t):  return (Fore.GREEN + t + Style.RESET_ALL) if COLORAMA else t
def yellow(t): return (Fore.YELLOW + t + Style.RESET_ALL) if COLORAMA else t
def cyan(t):   return (Fore.CYAN + t + Style.RESET_ALL) if COLORAMA else t
def bold(t):  
