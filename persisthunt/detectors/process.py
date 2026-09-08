import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Union, Dict, List, Set, Any
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector

@dataclass
class ProcessEntry:
    pid: int
    ppid: int
    comm: str
    exe: Optional[str]
    cmdline: str
    uid: int

class ProcessDetector(BaseDetector):
    """Detector for Linux process persistence and runtime anomalies.

    Inspects running processes via /proc to identify:
    - Binaries executing from temporary or staging directories (/tmp, /var/tmp, /dev/shm)
    - Binaries executing from hidden directory paths
    - Running processes whose executable file was deleted from disk (deleted binary persistence)
    - Suspicious parent-child relationships (e.g., web servers or database engines spawning shells)
    - Suspicious command lines (reverse shells, piped downloads, encoded payloads)
    - Inline script interpreter execution

    Strictly read-only:
    - Never signals or terminates processes (no os.kill).
    - Never attaches debuggers (no ptrace).
    - Never modifies process memory or environment.
    - Automatically sanitizes command-line arguments to mask passwords and tokens.
    """

    name: str = "Process Persistence Detector"
    detector_id: str = "process"

    # Common temporary/staging directories
    TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")

    # Server daemons that should generally never spawn interactive shells
    SERVER_DAEMONS = {
        "nginx",
        "httpd",
        "apache2",
        "lighttpd",
        "caddy",
        "php-fpm",
        "php-fpm7.4",
        "php-fpm8.0",
        "php-fpm8.1",
        "php-fpm8.2",
        "gunicorn",
        "uwsgi",
        "node",
        "mysqld",
        "mariadbd",
        "postgres",
        "redis-server",
        "memcached",
    }

    # Interactive shells and script interpreters
    SHELL_NAMES = {
        "bash",
        "sh",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "ash",
    }

    # Sensitive argument sanitization patterns
    REDACTION_PATTERNS = [
        (re.compile(r'(--password[=\s]+)(\S+)', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(-p\s+)(\S+)', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(--token[=\s]+)(\S+)', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(--api[-_]?key[=\s]+)(\S+)', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(api[-_]?key[=\s]+)(\S+)', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(secret[=\s]+)(\S+)', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(auth[=\s]+)(\S+)', re.IGNORECASE), r'\1***REDACTED***'),
    ]

    def __init__(
        self,
        proc_dir: Optional[Union[str, Path]] = None,
        root_prefix: Optional[Union[str, Path]] = None,
    ):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.root_prefix = Path(root_prefix) if root_prefix else None

        if proc_dir is not None:
            self.proc_dir = Path(proc_dir)
        elif self.root_prefix is not None:
            self.proc_dir = self.root_prefix / "proc"
        else:
            self.proc_dir = Path("/proc")

    @classmethod
    def sanitize_cmdline(cls, cmdline: str) -> str:
        """Sanitize command line by masking passwords, keys, and tokens."""
        sanitized = cmdline
        for pattern, repl in cls.REDACTION_PATTERNS:
            sanitized = pattern.sub(repl, sanitized)
        return sanitized

    def scan(self) -> FindingCollection:
        """Perform read-only process persistence audit."""
        collection = FindingCollection()

        if not self.proc_dir.exists() or not self.proc_dir.is_dir():
            collection.add(Finding(
                id="PH-PROC-090",
                category="process",
                severity=Severity.INFO,
                title="Process directory unavailable",
                description=f"Process directory {self.proc_dir} does not exist or is inaccessible.",
                location=str(self.proc_dir),
                recommendation="Verify proc filesystem mount or configuration."
            ))
            return collection

        # 1. Enumerate all running processes safely
        processes = self._collect_processes(collection)

        # 2. Audit each process and evaluate indicators
        for proc in processes.values():
            self._audit_process(proc, processes, collection)

        return collection

    def _collect_processes(self, collection: FindingCollection) -> Dict[int, ProcessEntry]:
        """Collect process metadata from proc_dir without modifying processes."""
        processes: Dict[int, ProcessEntry] = {}

        try:
            entries = os.scandir(self.proc_dir)
        except PermissionError as e:
            collection.add(Finding(
                id="PH-PROC-090",
                category="process",
                severity=Severity.INFO,
                title="Permission denied reading process directory",
                description=f"Could not read process directory at {self.proc_dir}.",
                evidence=str(e),
                location=str(self.proc_dir),
                recommendation="Run PersistHunt with elevated privileges if system-wide process enumeration is required."
            ))
            return processes
        except OSError:
            return processes

        with entries:
            for entry in entries:
                if not entry.name.isdigit():
                    continue

                pid = int(entry.name)
                proc_entry = self._read_process_entry(pid, Path(entry.path))
                if proc_entry is not None:
                    processes[pid] = proc_entry

        return processes

    def _read_process_entry(self, pid: int, pid_dir: Path) -> Optional[ProcessEntry]:
        """Read metadata for a single process directory safely."""
        try:
            # 1. Read status file for comm, PPid, and Uid
            comm = ""
            ppid = 0
            uid = 0
            status_file = pid_dir / "status"
            if status_file.exists():
                try:
                    for line in status_file.read_text(errors="replace").splitlines():
                        if line.startswith("Name:"):
                            comm = line.split(":", 1)[1].strip()
                        elif line.startswith("PPid:"):
                            ppid_str = line.split(":", 1)[1].strip()
                            ppid = int(ppid_str) if ppid_str.isdigit() else 0
                        elif line.startswith("Uid:"):
                            parts = line.split(":", 1)[1].strip().split()
                            if parts and parts[0].isdigit():
                                uid = int(parts[0])
                except (OSError, PermissionError):
                    pass

            # 2. Read exe symlink target (without executing)
            exe: Optional[str] = None
            exe_link = pid_dir / "exe"
            try:
                exe = os.readlink(exe_link)
            except (OSError, PermissionError):
                pass

            # 3. Read cmdline
            cmdline = ""
            cmdline_file = pid_dir / "cmdline"
            try:
                if cmdline_file.exists():
                    raw = cmdline_file.read_bytes()
                    args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\x00") if part]
                    cmdline = " ".join(args)
            except (OSError, PermissionError):
                pass

            # Fallback to comm if cmdline is empty
            if not cmdline and comm:
                cmdline = f"[{comm}]"

            return ProcessEntry(
                pid=pid,
                ppid=ppid,
                comm=comm,
                exe=exe,
                cmdline=cmdline,
                uid=uid,
            )
        except (OSError, PermissionError):
            return None

    def _audit_process(
        self,
        proc: ProcessEntry,
        all_processes: Dict[int, ProcessEntry],
        collection: FindingCollection,
    ) -> None:
        """Audit a single process entry against persistence indicators."""
        clean_cmdline = self.sanitize_cmdline(proc.cmdline)
        loc = f"PID {proc.pid} ({proc.comm})"

        # 1. Deleted binary still running in memory
        if proc.exe and proc.exe.endswith(" (deleted)"):
            collection.add(Finding(
                id="PH-PROC-003",
                category="process",
                severity=Severity.HIGH,
                title="Process running with deleted executable binary on disk",
                description=(
                    f"Process PID {proc.pid} ({proc.comm}) is executing binary '{proc.exe}', "
                    "which has been removed from the filesystem. Attackers commonly delete dropped "
                    "payloads immediately after execution to evade disk-based file inspection."
                ),
                evidence=f"exe: {proc.exe}, cmdline: {clean_cmdline}",
                location=loc,
                recommendation="Investigate the process origin, preserve process memory if forensic capture is needed, and inspect network sockets."
            ))

        # 2. Execution from temporary or staging directories (/tmp, /var/tmp, /dev/shm)
        is_temp_exe = False
        if proc.exe:
            clean_exe = proc.exe.removesuffix(" (deleted)")
            is_temp_exe = any(clean_exe.startswith(td) for td in self.TEMP_DIRS)

        is_temp_cmd = any(td in clean_cmdline for td in self.TEMP_DIRS)

        if is_temp_exe or is_temp_cmd:
            collection.add(Finding(
                id="PH-PROC-001",
                category="process",
                severity=Severity.HIGH,
                title="Process executing from temporary or staging directory",
                description=(
                    f"Process PID {proc.pid} ({proc.comm}) executes a binary or script located in a "
                    "temporary directory. Temporary paths are world-writable and frequently used "
                    "for staging unauthorized backdoors and persistence payloads."
                ),
                evidence=f"exe: {proc.exe or 'unknown'}, cmdline: {clean_cmdline}",
                location=loc,
                recommendation="Identify what initiated the process, terminate unauthorized instances, and inspect corresponding filesystem files."
            ))

        # 3. Execution from hidden directory path
        if proc.exe:
            clean_exe = proc.exe.removesuffix(" (deleted)")
            # Check for hidden directories in path (e.g. /home/user/.hidden/tool)
            path_parts = Path(clean_exe).parts
            # Look for parts starting with '.' that are not '.' or '..'
            hidden_dirs = [p for p in path_parts[:-1] if p.startswith(".") and p not in (".", "..")]
            if hidden_dirs:
                collection.add(Finding(
                    id="PH-PROC-002",
                    category="process",
                    severity=Severity.HIGH,
                    title="Process executing from hidden directory path",
                    description=(
                        f"Process PID {proc.pid} ({proc.comm}) executes from a hidden directory path "
                        f"('{clean_exe}'). Malicious persistence often utilizes hidden folders to evade detection."
                    ),
                    evidence=f"exe: {proc.exe}, cmdline: {clean_cmdline}",
                    location=loc,
                    recommendation="Verify the legitimacy of the hidden software path and inspect directory contents."
                ))

        # 4. Suspicious parent-child process relationships
        if proc.ppid in all_processes:
            parent = all_processes[proc.ppid]
            parent_comm_lower = parent.comm.lower()
            parent_name = parent_comm_lower
            if parent.exe:
                parent_name = Path(parent.exe.removesuffix(" (deleted)")).name.lower()

            # Check if parent is a server daemon and child is an interactive shell
            proc_comm_lower = proc.comm.lower()
            if parent_name in self.SERVER_DAEMONS and proc_comm_lower in self.SHELL_NAMES:
                collection.add(Finding(
                    id="PH-PROC-005",
                    category="process",
                    severity=Severity.HIGH,
                    title="Web server or service daemon spawned interactive shell",
                    description=(
                        f"Daemon process '{parent.comm}' (PID {parent.pid}) spawned an interactive shell "
                        f"'{proc.comm}' (PID {proc.pid}). This pattern frequently indicates an active web shell, "
                        "remote code execution (RCE) exploitation, or server compromise."
                    ),
                    evidence=f"Parent PID {parent.pid} ({parent.comm}) -> Child PID {proc.pid} ({clean_cmdline})",
                    location=loc,
                    recommendation="Investigate web server access logs and active child connections immediately. Isolate server if compromised."
                ))

        # 5. Suspicious command line execution (reverse shells, download pipes, encoded payloads)
        cmd_lower = clean_cmdline.lower()

        # 5a. Network socket redirection / reverse shells
        if "/dev/tcp/" in cmd_lower or "/dev/udp/" in cmd_lower or "mkfifo" in cmd_lower:
            collection.add(Finding(
                id="PH-PROC-004",
                category="process",
                severity=Severity.HIGH,
                title="Process command line contains raw socket redirection or named pipe",
                description=(
                    f"Process PID {proc.pid} contains network socket redirection syntax (/dev/tcp or /dev/udp) "
                    "or named pipes, characteristic of interactive reverse shells."
                ),
                evidence=clean_cmdline,
                location=loc,
                recommendation="Investigate active network connections (ss -tp) for this process immediately."
            ))
        elif re.search(r'\b(nc|ncat|netcat|socat)\b.*(\s+-e\s+|\s+exec:|\s+system:)', cmd_lower):
            collection.add(Finding(
                id="PH-PROC-004",
                category="process",
                severity=Severity.HIGH,
                title="Process executing interactive network utility with command execution",
                description=(
                    f"Process PID {proc.pid} is running a network utility with executable binding options (-e / exec:), "
                    "indicative of a network listener or reverse shell."
                ),
                evidence=clean_cmdline,
                location=loc,
                recommendation="Inspect the listening or connected endpoint and verify administrative purpose."
            ))
        # 5b. Download piped into shell
        elif re.search(r'\b(curl|wget)\b.*\|\s*(bash|sh|dash|zsh)', cmd_lower):
            collection.add(Finding(
                id="PH-PROC-004",
                category="process",
                severity=Severity.HIGH,
                title="Process executing remote download piped directly into shell",
                description=(
                    f"Process PID {proc.pid} is piping downloaded content directly into a shell interpreter. "
                    "This is a high-risk remote code execution pattern."
                ),
                evidence=clean_cmdline,
                location=loc,
                recommendation="Verify the remote download source URL and audit downloaded script payloads."
            ))
        # 5c. Encoded payload execution
        elif re.search(r'\bbase64\s+(-d|--decode)\b.*\|\s*(bash|sh|dash|zsh)', cmd_lower):
            collection.add(Finding(
                id="PH-PROC-004",
                category="process",
                severity=Severity.HIGH,
                title="Process executing base64-decoded pipeline payload",
                description=(
                    f"Process PID {proc.pid} is decoding and executing base64 data directly in a shell pipeline. "
                    "Obfuscation through encoding is a common evasion technique."
                ),
                evidence=clean_cmdline,
                location=loc,
                recommendation="Decode and analyze the base64 payload to determine its operational intent."
            ))

        # 6. Inline interpreter execution
        if re.search(r'\b(python|python3|perl|ruby|lua)\b.*\s+-[ce]\b', clean_cmdline) or \
           re.search(r'\b(php)\b.*\s+-r\b', clean_cmdline):
            if not any(f.id in ("PH-PROC-004", "PH-PROC-005") for f in collection):
                collection.add(Finding(
                    id="PH-PROC-006",
                    category="process",
                    severity=Severity.MEDIUM,
                    title="Process executing inline interpreter command script",
                    description=(
                        f"Process PID {proc.pid} ({proc.comm}) executes inline interpreter script arguments. "
                        "Inline execution can be used for stealthy ephemeral code execution."
                    ),
                    evidence=clean_cmdline,
                    location=loc,
                    recommendation="Review the inline command logic to ensure legitimate operational purpose."
                ))
