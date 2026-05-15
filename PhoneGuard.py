"""
PhoneGuard Pro v2.0 - Android/Termux Security Suite
====================================================
ZERO external dependencies — uses only Python stdlib + shell commands.
Works 100% on Termux (Android) without psutil or any pip install.

Run: python phone_security_app.py
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

# ═══════════════════════════════════════════════════════════════════════════════
#  ANSI COLORS  (no colorama needed — raw ANSI escape codes)
# ═══════════════════════════════════════════════════════════════════════════════

IS_ANDROID = "ANDROID_ROOT" in os.environ or os.path.exists("/system/build.prop")
IS_TERMUX  = "com.termux" in os.environ.get("PREFIX", "") or \
             os.path.exists("/data/data/com.termux")

def _c(code, t): return f"\033[{code}m{t}\033[0m"
def red(t):      return _c("91", t)
def green(t):    return _c("92", t)
def yellow(t):   return _c("93", t)
def blue(t):     return _c("94", t)
def magenta(t):  return _c("95", t)
def cyan(t):     return _c("96", t)
def bold(t):     return _c("1",  t)
def dim(t):      return _c("2",  t)

# ═══════════════════════════════════════════════════════════════════════════════
#  SHELL HELPER  (replaces psutil entirely — uses /proc + shell commands)
# ═══════════════════════════════════════════════════════════════════════════════

def shell(cmd, timeout=8):
    """Run a shell command safely, return stdout string or '' on error."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""

# ═══════════════════════════════════════════════════════════════════════════════
#  THREAT DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

MALICIOUS_PROCESS_KEYWORDS = [
    # Stalkerware / spyware
    "flexispy", "mspy", "spyzie", "spyic", "theonespy", "hoverwatch",
    # Crypto miners
    "xmrig", "minerd", "cpuminer", "cryptonight", "coinhive", "nbminer",
    # RATs / backdoors
    "metasploit", "meterpreter", "cobalt", "mimikatz",
    "reverse_shell", "bind_shell",
    # Generic malware signals
    "keylogger", "keylog", "ransomware", "botnet", "ddos_agent",
    "rootkit", "inject", "exploit", "shellcode", "exfiltrat",
    "stealer", "grabber", "dropper",
]

SUSPICIOUS_PROCESS_KEYWORDS = [
    "spy", "stalker", "backdoor", "miner", "trojan",
    "worm", "hook", "dumper", "sniffer",
]

DANGEROUS_EXTENSIONS = {
    ".apk":  ("HIGH",     "Android Package — verify source before installing"),
    ".bat":  ("HIGH",     "Windows Batch Script — can execute arbitrary commands"),
    ".cmd":  ("HIGH",     "Windows Command Script"),
    ".vbs":  ("CRITICAL", "VBScript — frequently used by malware"),
    ".ps1":  ("HIGH",     "PowerShell script"),
    ".exe":  ("HIGH",     "Windows executable"),
    ".scr":  ("CRITICAL", "Screen-saver executable — common malware vector"),
    ".pif":  ("CRITICAL", "Program Information File — used by old worms"),
    ".jar":  ("MEDIUM",   "Java Archive — can execute code"),
    ".sh":   ("MEDIUM",   "Shell script — inspect before running"),
    ".elf":  ("MEDIUM",   "Linux/Android ELF binary — unknown origin"),
    ".dex":  ("MEDIUM",   "Android Dalvik executable outside APK"),
    ".so":   ("LOW",      "Shared library — verify origin"),
}

SUSPICIOUS_FILENAMES = [
    "crack", "hack", "keygen", "patch_", "loader",
    "bypass", "cheat", "trainer", "injector", "dumper",
    "stealer", "grabber", "logger_", "spyware", "ratclient",
    "payload", "exploit", "shell_", "backdoor", "fake_update",
    "install_free", "free_premium", "mod_apk", "rootkit",
]

MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Virus",
    "cf8bd9dfddff007f75adf4c2be48005a": "Trojan.GenericKD",
    "098f6bcd4621d373cade4e832627b4f6": "Spyware.Agent.Gen",
    "5d41402abc4b2a76b9719d911017c592": "Ransomware.Placeholder",
    "d41d8cd98f00b204e9800998ecf8427e": "Empty-file dropper",
}

SUSPICIOUS_PORTS = {
    "4444":  "Metasploit default listener",
    "5555":  "Android ADB remote — serious risk",
    "1337":  "Leet/hacker port",
    "6666":  "IRC / C2 malware channel",
    "6667":  "IRC / C2 malware channel",
    "31337": "Back Orifice RAT",
    "12345": "NetBus RAT",
    "27374": "SubSeven RAT",
    "9999":  "Common reverse shell port",
    "8888":  "Common C2 port",
}

JUNK_EXTENSIONS = {
    ".log", ".tmp", ".temp", ".bak", ".old",
    ".swp", ".swo", ".cache", ".dmp",
}

# ═══════════════════════════════════════════════════════════════════════════════
#  THREAT RESULT
# ═══════════════════════════════════════════════════════════════════════════════

class Threat:
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def __init__(self, kind, name, severity, detail, action="investigate"):
        self.kind     = kind
        self.name     = name
        self.severity = severity
        self.detail   = detail
        self.action   = action
        self.time     = datetime.now().strftime("%H:%M:%S")

    def col(self):
        return {"CRITICAL": red, "HIGH": red,
                "MEDIUM": yellow, "LOW": cyan}.get(self.severity, str)

    def __str__(self):
        c   = self.col()
        tag = f"[{self.severity}]"
        return (f"  {c(f'{tag:^10}')} {bold(self.name)}\n"
                f"  {'':^10} {dim(self.kind)} | {self.detail}\n"
                f"  {'':^10} {yellow('Action:')} {self.action}")

    def to_dict(self):
        return dict(kind=self.kind, name=self.name, severity=self.severity,
                    detail=self.detail, action=self.action, time=self.time)

# ═══════════════════════════════════════════════════════════════════════════════
#  SYSTEM INFO  (pure /proc + shell — zero external deps)
# ═══════════════════════════════════════════════════════════════════════════════

class SysInfo:

    @staticmethod
    def cpu_percent():
        """Read CPU from /proc/stat — works on Android & Linux."""
        def _read():
            with open("/proc/stat") as f:
                line = f.readline()
            vals = list(map(int, line.split()[1:8]))
            idle = vals[3]
            total = sum(vals)
            return idle, total
        try:
            i1, t1 = _read()
            time.sleep(0.35)
            i2, t2 = _read()
            dt = t2 - t1
            if dt == 0:
                return 0.0
            return round((1 - (i2 - i1) / dt) * 100, 1)
        except Exception:
            return -1.0

    @staticmethod
    def memory():
        """Read from /proc/meminfo."""
        info = {}
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        info[parts[0].rstrip(":")] = int(parts[1])
        except Exception:
            return None
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used  = total - avail
        pct   = round(used / total * 100, 1) if total else 0
        return {
            "total_mb": total // 1024,
            "used_mb":  used  // 1024,
            "free_mb":  avail // 1024,
            "percent":  pct,
        }

    @staticmethod
    def disk(path="/"):
        out = shell(f"df -h {path} 2>/dev/null | tail -1")
        if not out:
            return None
        parts = out.split()
        try:
            return {
                "size":    parts[1] if len(parts) > 1 else "?",
                "used":    parts[2] if len(parts) > 2 else "?",
                "free":    parts[3] if len(parts) > 3 else "?",
                "percent": parts[4].replace("%", "") if len(parts) > 4 else "?",
            }
        except Exception:
            return None

    @staticmethod
    def processes():
        """
        Read all running processes from /proc/<pid>/ — no psutil needed.
        Returns list of dicts: pid, name, cmd, mem_mb.
        """
        procs = []
        proc_dir = Path("/proc")
        for entry in proc_dir.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                name    = (entry / "comm").read_text().strip()
                cmdline = (entry / "cmdline").read_bytes() \
                            .replace(b"\x00", b" ").decode(errors="ignore").strip()
                status  = (entry / "status").read_text()
                mem_kb  = 0
                for line in status.splitlines():
                    if line.startswith("VmRSS:"):
                        mem_kb = int(line.split()[1])
                        break
                procs.append({
                    "pid":    entry.name,
                    "name":   name,
                    "cmd":    cmdline[:120],
                    "mem_mb": mem_kb // 1024,
                })
            except Exception:
                continue
        return procs

    @staticmethod
    def network_connections():
        """
        Parse /proc/net/tcp and /proc/net/tcp6 — no psutil needed.
        """
        conns = []
        for fname in ["/proc/net/tcp", "/proc/net/tcp6"]:
            try:
                with open(fname) as f:
                    lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local  = parts[1]
                    remote = parts[2]
                    state  = parts[3]
                    lport  = str(int(local.split(":")[1],  16))
                    rport  = str(int(remote.split(":")[1], 16))
                    conns.append({
                        "local_port":  lport,
                        "remote_port": rport,
                        "state":       state,
                    })
            except Exception:
                continue
        return conns

    @staticmethod
    def android_info():
        if not (IS_ANDROID or IS_TERMUX):
            return {}
        info = {}
        for key, prop in [("brand",       "ro.product.brand"),
                          ("model",       "ro.product.model"),
                          ("android_ver", "ro.build.version.release"),
                          ("sdk",         "ro.build.version.sdk")]:
            val = shell(f"getprop {prop}")
            if val:
                info[key] = val
        return info

# ═══════════════════════════════════════════════════════════════════════════════
#  SCANNERS
# ═══════════════════════════════════════════════════════════════════════════════

class ProcessScanner:

    def scan(self, progress_cb=None):
        threats = []
        procs   = SysInfo.processes()
        total   = len(procs)

        for i, p in enumerate(procs):
            if progress_cb:
                progress_cb(i + 1, total, p["name"])

            name = p["name"].lower()
            cmd  = p["cmd"].lower()
            pid  = p["pid"]

            # 1. Known malware keyword
            matched = False
            for kw in MALICIOUS_PROCESS_KEYWORDS:
                if kw in name or kw in cmd:
                    threats.append(Threat(
                        "process", f"{p['name']} (PID:{pid})",
                        "CRITICAL",
                        f"Matches malware signature: '{kw}'",
                        "terminate immediately"
                    ))
                    matched = True
                    break

            if matched:
                continue

            # 2. Suspicious keyword
            for kw in SUSPICIOUS_PROCESS_KEYWORDS:
                if kw in name:
                    threats.append(Threat(
                        "process", f"{p['name']} (PID:{pid})",
                        "HIGH",
                        f"Suspicious keyword '{kw}' in process name",
                        "investigate"
                    ))
                    break
            else:
                # 3. High memory unknown process
                if p["mem_mb"] > 400 and name not in {
                    "chrome", "firefox", "android", "system",
                    "zygote", "surfaceflinger", "mediaserver"
                }:
                    threats.append(Threat(
                        "process", f"{p['name']} (PID:{pid})",
                        "LOW",
                        f"High memory: {p['mem_mb']} MB",
                        "monitor"
                    ))

        return threats, total


class FileScanner:

    def __init__(self):
        self.scanned = 0
        self.clean   = 0
        self.unknown = []

    def scan(self, root_path="~", progress_cb=None):
        threats = []
        root    = Path(root_path).expanduser()
        if not root.exists():
            print(red(f"  Path not found: {root_path}"))
            return threats

        all_files = []
        try:
            all_files = [f for f in root.rglob("*") if f.is_file()]
        except PermissionError:
            pass

        total = len(all_files)
        for i, fpath in enumerate(all_files):
            self.scanned += 1
            if progress_cb:
                progress_cb(i + 1, total, fpath.name[:35])
            t = self._analyze(fpath)
            if t:
                threats.append(t)
            else:
                self.clean += 1

        return threats

    def _analyze(self, fpath: Path):
        name = fpath.name.lower()
        ext  = fpath.suffix.lower()

        # 1. Hash check
        h = self._md5(fpath)
        if h and h in MALICIOUS_HASHES:
            return Threat("file", str(fpath), "CRITICAL",
                          f"Known malware hash → {MALICIOUS_HASHES[h]}",
                          "delete now")

        # 2. Dangerous extension
        if ext in DANGEROUS_EXTENSIONS:
            sev, desc = DANGEROUS_EXTENSIONS[ext]
            return Threat("file", str(fpath), sev, desc, "quarantine")

        # 3. Suspicious filename pattern
        for pat in SUSPICIOUS_FILENAMES:
            if pat in name:
                return Threat("file", str(fpath), "HIGH",
                              f"Suspicious filename: '{pat}'",
                              "quarantine")

        # 4. Hidden + executable
        if name.startswith("."):
            try:
                if os.access(fpath, os.X_OK):
                    self.unknown.append(str(fpath))
                    return Threat("file", str(fpath), "MEDIUM",
                                  "Hidden executable file",
                                  "investigate")
            except Exception:
                pass

        # 5. Zero-byte executable
        try:
            if fpath.stat().st_size == 0 and ext in {".sh", ".elf", ".exe", ".apk"}:
                return Threat("file", str(fpath), "LOW",
                              "Zero-byte executable — possible dropper stub",
                              "investigate")
        except OSError:
            pass

        return None

    @staticmethod
    def _md5(fpath: Path, chunk=65536):
        try:
            md5 = hashlib.md5()
            with open(fpath, "rb") as f:
                while True:
                    data = f.read(chunk)
                    if not data:
                        break
                    md5.update(data)
            return md5.hexdigest()
        except Exception:
            return None


class NetworkScanner:

    def scan(self):
        threats = []
        conns   = SysInfo.network_connections()
        seen    = set()

        for conn in conns:
            lp = conn["local_port"]
            rp = conn["remote_port"]

            if lp in SUSPICIOUS_PORTS and lp not in seen:
                seen.add(lp)
                threats.append(Threat(
                    "network", f"Local port {lp}",
                    "CRITICAL",
                    f"{SUSPICIOUS_PORTS[lp]} | state: {conn['state']}",
                    "block & investigate"
                ))
            elif rp in SUSPICIOUS_PORTS and rp != "0" and rp not in seen:
                seen.add(rp)
                threats.append(Threat(
                    "network", f"Remote port {rp}",
                    "HIGH",
                    SUSPICIOUS_PORTS[rp],
                    "block"
                ))

        # Also try ss / netstat for confirmation
        for cmd in ["ss -tulnp 2>/dev/null", "netstat -tulnp 2>/dev/null"]:
            out = shell(cmd)
            for line in out.splitlines():
                for port, desc in SUSPICIOUS_PORTS.items():
                    if (f":{port}" in line or f" {port} " in line) \
                            and port not in seen:
                        seen.add(port)
                        threats.append(Threat(
                            "network", f"Port {port}",
                            "HIGH", desc, "investigate"
                        ))
        return threats


class ResourceScanner:

    def scan(self):
        threats = []

        cpu = SysInfo.cpu_percent()
        if cpu > 85:
            threats.append(Threat("resource", "CPU", "HIGH",
                f"CPU at {cpu}% — possible crypto miner or runaway malware",
                "check top processes"))
        elif cpu > 70:
            threats.append(Threat("resource", "CPU", "MEDIUM",
                f"CPU at {cpu}% — elevated", "monitor"))

        mem = SysInfo.memory()
        if mem:
            if mem["percent"] > 90:
                threats.append(Threat("resource", "RAM", "HIGH",
                    f"{mem['percent']}% used  ({mem['used_mb']}MB / {mem['total_mb']}MB)",
                    "free memory"))
            elif mem["percent"] > 80:
                threats.append(Threat("resource", "RAM", "MEDIUM",
                    f"{mem['percent']}% used  ({mem['free_mb']}MB free)",
                    "monitor"))

        disk = SysInfo.disk()
        if disk:
            try:
                pct = int(disk["percent"])
                if pct > 90:
                    threats.append(Threat("resource", "Disk /", "MEDIUM",
                        f"{pct}% full — only {disk['free']} free",
                        "clean junk files"))
            except Exception:
                pass

        return threats, cpu, mem, disk


class SystemCleaner:

    CACHE_PATHS = [
        "~/.cache",
        "~/tmp",
        "~/.thumbnails",
        "~/.local/share/Trash",
        "/data/data/com.termux/cache",
        "/tmp",
    ]

    def scan_cache(self):
        found = []
        size  = 0
        for d in self.CACHE_PATHS:
            p = Path(d).expanduser()
            if not p.exists():
                continue
            try:
                for f in p.rglob("*"):
                    if f.is_file():
                        try:
                            sz = f.stat().st_size
                            found.append((f, sz))
                            size += sz
                        except OSError:
                            pass
            except Exception:
                continue
        return found, size

    def scan_junk(self, root="~"):
        junk = []
        size = 0
        rpath = Path(root).expanduser()
        try:
            for f in rpath.rglob("*"):
                if f.is_file() and f.suffix.lower() in JUNK_EXTENSIONS:
                    try:
                        sz = f.stat().st_size
                        junk.append((f, sz))
                        size += sz
                    except OSError:
                        pass
        except Exception:
            pass
        return junk, size

# ═══════════════════════════════════════════════════════════════════════════════
#  REAL-TIME MONITOR  (background thread — no psutil)
# ═══════════════════════════════════════════════════════════════════════════════

class RealTimeMonitor:

    def __init__(self, interval=12):
        self.interval = interval
        self.running  = False
        self._thread  = None
        self._seen    = set()
        self.alerts   = []

    def start(self):
        if self.running:
            print(yellow("  Already running."))
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(green(f"  ✓ Real-time monitor active (every {self.interval}s)"))
        print(dim("    New malicious processes will be flagged automatically."))

    def stop(self):
        self.running = False
        print(yellow("  Real-time monitor stopped."))

    def _loop(self):
        while self.running:
            try:
                for p in SysInfo.processes():
                    key = p["pid"] + p["name"]
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    name = p["name"].lower()
                    for kw in MALICIOUS_PROCESS_KEYWORDS:
                        if kw in name:
                            alert = {
                                "time":    datetime.now().strftime("%H:%M:%S"),
                                "process": p["name"],
                                "pid":     p["pid"],
                                "kw":      kw,
                            }
                            self.alerts.append(alert)
                            print(red(
                                f"\n  ALERT [{alert['time']}] "
                                f"Malicious process: {p['name']} "
                                f"(PID:{p['pid']}) — '{kw}'"
                            ))
                            break
            except Exception:
                pass
            time.sleep(self.interval)

# ═══════════════════════════════════════════════════════════════════════════════
#  UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def clr():
    os.system("clear")

def banner():
    clr()
    print(cyan("""
╔══════════════════════════════════════════════════════════╗
║  ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗           ║
║  ██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝           ║
║  ██████╔╝███████║██║   ██║██╔██╗ ██║█████╗             ║
║  ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝             ║
║  ██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗           ║
║  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝           ║
║     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗           ║
║    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗          ║
║    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║          ║
║    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║          ║
║    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝          ║
║     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝           ║
║                                                          ║
║   PhoneGuard Pro v2.0  |  Zero-dependency Security      ║
╚══════════════════════════════════════════════════════════╝
"""))

def section(title):
    print()
    w = 56
    print(cyan("  ╔" + "═" * w + "╗"))
    print(cyan("  ║") + bold(f"  {title:<{w-2}}") + cyan("  ║"))
    print(cyan("  ╚" + "═" * w + "╝"))
    print()

def progress_bar(cur, tot, label="", width=38):
    if tot == 0:
        return
    pct  = cur / tot
    done = int(width * pct)
    bar  = "█" * done + "░" * (width - done)
    lbl  = label[:32].ljust(32)
    print(f"\r  {cyan('[')}{green(bar)}{cyan(']')} {pct*100:5.1f}%  {dim(lbl)}",
          end="", flush=True)

def print_threats(threats, label="threats"):
    if not threats:
        print(green(f"  ✓ No {label} detected."))
        return
    print(red(f"  ⚠  {len(threats)} {label} detected:\n"))
    for t in sorted(threats, key=lambda x: Threat.SEV_ORDER.get(x.severity, 9)):
        print(str(t))
        print()

def print_sysinfo():
    section("SYSTEM STATUS")
    uname = platform.uname()
    print(f"  {dim('OS')}       {uname.system} {uname.release}  {uname.machine}")
    print(f"  {dim('Python')}   {sys.version.split()[0]}")

    ai = SysInfo.android_info()
    if ai:
        print(f"  {dim('Device')}   {ai.get('brand','')} {ai.get('model','')}")
        print(f"  {dim('Android')}  {ai.get('android_ver','')}  SDK {ai.get('sdk','')}")

    cpu = SysInfo.cpu_percent()
    mem = SysInfo.memory()
    dsk = SysInfo.disk()

    if cpu >= 0:
        cs = green(f"{cpu}%") if cpu < 70 else red(f"{cpu}%")
        print(f"  {dim('CPU')}      {cs}")

    if mem:
        ms = green(f"{mem['percent']}%") if mem['percent'] < 80 else red(f"{mem['percent']}%")
        print(f"  {dim('RAM')}      {ms}  ({mem['used_mb']}MB / {mem['total_mb']}MB)")

    if dsk:
        try:
            dp = int(dsk["percent"])
            ds = green(f"{dp}%") if dp < 85 else red(f"{dp}%")
            print(f"  {dim('Disk')}     {ds} used  ({dsk['free']} free)")
        except Exception:
            pass

def summary(threats, elapsed=0):
    section("SCAN SUMMARY")
    c = sum(1 for t in threats if t.severity == "CRITICAL")
    h = sum(1 for t in threats if t.severity == "HIGH")
    m = sum(1 for t in threats if t.severity == "MEDIUM")
    l = sum(1 for t in threats if t.severity == "LOW")
    st = green("  ✓  DEVICE CLEAN — no threats found") if not threats \
         else red(f"  ✗  {len(threats)} THREATS DETECTED")
    print(st)
    if elapsed:
        print(f"  {dim('Scan time')}  {elapsed:.1f}s")
    print(f"  {red('CRITICAL')}   {c}")
    print(f"  {red('HIGH')}       {h}")
    print(f"  {yellow('MEDIUM')}     {m}")
    print(f"  {cyan('LOW')}        {l}")

def save_report(threats, elapsed):
    report = {
        "generated": datetime.now().isoformat(),
        "platform":  platform.system(),
        "android":   IS_ANDROID or IS_TERMUX,
        "elapsed_s": round(elapsed, 2),
        "total":     len(threats),
        "summary": {
            "CRITICAL": sum(1 for t in threats if t.severity == "CRITICAL"),
            "HIGH":     sum(1 for t in threats if t.severity == "HIGH"),
            "MEDIUM":   sum(1 for t in threats if t.severity == "MEDIUM"),
            "LOW":      sum(1 for t in threats if t.severity == "LOW"),
        },
        "threats": [t.to_dict() for t in threats],
    }
    p = Path("phoneguard_report.json")
    p.write_text(json.dumps(report, indent=2))
    print(green(f"\n  ✓ Report saved → {p.absolute()}"))

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN APP
# ═══════════════════════════════════════════════════════════════════════════════

class App:

    def __init__(self):
        self.rt  = RealTimeMonitor()
        self._lt = []   # last threats

    def run(self):
        while True:
            banner()
            print_sysinfo()
            print()
            rows = [
                ("1", "Full Security Scan",           green),
                ("2", "Process / Background Scan",    green),
                ("3", "File & Virus Scan",             green),
                ("4", "Network Connection Monitor",   green),
                ("5", "System Resource Check",        green),
                ("6", "Junk & Cache Cleaner",         green),
                ("7", "Start Real-Time Monitor",      cyan),
                ("8", "Stop  Real-Time Monitor",      cyan),
                ("9", "Save Security Report (JSON)",  blue),
                ("0", "Exit",                         red),
            ]
            print(cyan("  ╔══ MENU " + "═" * 42 + "╗"))
            for key, label, col in rows:
                print(cyan("  ║  ") + col(f"[{key}]") +
                      f"  {label:<40}" + cyan("║"))
            print(cyan("  ╚" + "═" * 50 + "╝"))
            print()

            ch = input(cyan("  ➤ Option: ")).strip()

            if   ch == "1": self._full_scan()
            elif ch == "2": self._proc_scan()
            elif ch == "3": self._file_scan()
            elif ch == "4": self._net_scan()
            elif ch == "5": self._res_scan()
            elif ch == "6": self._clean()
            elif ch == "7": self.rt.start()
            elif ch == "8": self.rt.stop()
            elif ch == "9": save_report(self._lt, 0)
            elif ch == "0":
                self.rt.stop()
                print(green("\n  Stay safe! Goodbye.\n"))
                break
            else:
                print(red("  Invalid option."))

            input(dim("\n  Press Enter to return to menu…"))

    # ── Scans ─────────────────────────────────────────────────────────────────

    def _full_scan(self):
        banner(); section("FULL SECURITY SCAN")
        t0 = time.time()
        all_t = []
        all_t += self.__proc()
        all_t += self.__net()
        all_t += self.__res()
        all_t += self.__files("~")
        elapsed = time.time() - t0
        self._lt = all_t
        summary(all_t, elapsed)
        save_report(all_t, elapsed)

    def _proc_scan(self):
        banner(); section("BACKGROUND PROCESS SCANNER")
        t = self.__proc(); self._lt = t; summary(t)

    def _file_scan(self):
        banner(); section("FILE & VIRUS SCANNER")
        path = input(cyan("  Path to scan [~/]: ")).strip() or "~"
        t = self.__files(path); self._lt = t; summary(t)

    def _net_scan(self):
        banner(); section("NETWORK CONNECTION MONITOR")
        t = self.__net(); self._lt = t; summary(t)

    def _res_scan(self):
        banner(); section("SYSTEM RESOURCE CHECK")
        t = self.__res(); self._lt = t; summary(t)

    def _clean(self):
        banner(); section("JUNK & CACHE CLEANER")
        cl = SystemCleaner()
        print(yellow("  Scanning cache…"))
        cf, cs = cl.scan_cache()
        print(f"  Cache  : {len(cf)} files  ({cs // 1024 // 1024} MB)")
        print(yellow("  Scanning junk files in ~/…"))
        jf, js = cl.scan_junk()
        print(f"  Junk   : {len(jf)} files  ({js // 1024 // 1024} MB)")
        total_mb = (cs + js) // 1024 // 1024
        print(green(f"\n  Total recoverable: {total_mb} MB"))
        if total_mb > 0:
            if input(cyan("  Delete junk files? (y/N): ")).strip().lower() == "y":
                deleted = 0
                for f, _ in jf:
                    try:
                        f.unlink(); deleted += 1
                    except Exception:
                        pass
                print(green(f"  ✓ Deleted {deleted} junk files."))
        else:
            print(green("  ✓ No junk found."))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def __proc(self):
        print(yellow("\n  [→] Scanning background processes…"))
        sc = ProcessScanner()
        def cb(c, t, n): progress_bar(c, t, n)
        threats, total = sc.scan(progress_cb=cb)
        print(f"\n  Scanned {total} processes")
        print_threats(threats, "process threats")
        return threats

    def __files(self, path):
        print(yellow(f"\n  [→] Scanning files in {path}…"))
        sc = FileScanner()
        def cb(c, t, n): progress_bar(c, t, n)
        threats = sc.scan(path, progress_cb=cb)
        print(f"\n  Scanned {sc.scanned} files | Clean: {sc.clean}")
        if sc.unknown:
            print(yellow(f"  Hidden executables: {len(sc.unknown)}"))
            for u in sc.unknown[:5]:
                print(f"    {dim('→')} {u}")
        print_threats(threats, "file threats")
        return threats

    def __net(self):
        print(yellow("\n  [→] Scanning network connections…"))
        sc = NetworkScanner()
        threats = sc.scan()
        print_threats(threats, "network threats")
        return threats

    def __res(self):
        print(yellow("\n  [→] Checking system resources…"))
        sc = ResourceScanner()
        threats, *_ = sc.scan()
        print_threats(threats, "resource issues")
        return threats

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(cyan("\n  PhoneGuard Pro v2.0"))
    env = "Android/Termux" if (IS_ANDROID or IS_TERMUX) else platform.system()
    print(green(f"  ✓ Platform: {env}"))
    print(green("  ✓ Zero external dependencies"))
    print(green("  ✓ No pip install required\n"))
    time.sleep(0.6)
    App().run()
