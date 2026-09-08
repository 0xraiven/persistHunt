import os
import re
from pathlib import Path
from typing import Optional, Union, Iterable, List, Set
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector

class CronDetector(BaseDetector):
    """Detector for Linux cron persistence mechanisms.

    Audits system crontabs (/etc/crontab, /etc/cron.d/), scheduled script
    directories (/etc/cron.hourly, /etc/cron.daily, etc.), and user crontabs
    (/var/spool/cron/crontabs, /var/spool/cron) for suspicious persistence
    indicators.

    Adheres to strict read-only auditing safety: never modifies files,
    never executes discovered commands, and never initiates network requests.
    """

    name: str = "Cron Persistence Detector"
    detector_id: str = "cron"

    # Default inspection targets on Linux
    DEFAULT_SYSTEM_CRONTAB = "/etc/crontab"
    DEFAULT_CRON_D_DIR = "/etc/cron.d"
    DEFAULT_SCRIPT_DIRS = [
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]
    DEFAULT_SPOOL_DIRS = [
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
    ]

    # Indicator Patterns
    RE_SOCKET_DEV = re.compile(r"/dev/(tcp|udp)/\S+", re.IGNORECASE)
    RE_NETCAT = re.compile(r"\b(nc|ncat|netcat|socat)\b", re.IGNORECASE)
    RE_MKFIFO = re.compile(r"\bmkfifo\b", re.IGNORECASE)
    RE_DOWNLOAD_PIPE = re.compile(
        r"\b(curl|wget)\b[^|;\n]*\|\s*(bash|sh|zsh|dash|python[0-9.]*|perl)\b",
        re.IGNORECASE,
    )
    RE_DOWNLOAD_TOOL = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)
    RE_TEMP_DIRS = re.compile(r"/(tmp|var/tmp|dev/shm)/\S*", re.IGNORECASE)
    RE_INLINE_INTERP = re.compile(
        r"(\b(python[0-9.]*|perl|ruby)\s+(-c|-e)\b|\b(bash|sh|zsh|dash)\s+-c\b)",
        re.IGNORECASE,
    )
    RE_BASE64_DECODE = re.compile(
        r"(\bbase64\s+(-d|--decode|-di)\b|\bbase64\b[^|;\n]*\|\s*(bash|sh|zsh|dash)\b)",
        re.IGNORECASE,
    )
    RE_ENV_VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")

    def __init__(
        self,
        root_prefix: Optional[Union[str, Path]] = None,
        system_crontab: Optional[Union[str, Path]] = None,
        cron_d_dir: Optional[Union[str, Path]] = None,
        script_dirs: Optional[Iterable[Union[str, Path]]] = None,
        spool_dirs: Optional[Iterable[Union[str, Path]]] = None,
    ):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.root_prefix = Path(root_prefix) if root_prefix else None

        self.system_crontab = self._resolve_path(system_crontab or self.DEFAULT_SYSTEM_CRONTAB)
        self.cron_d_dir = self._resolve_path(cron_d_dir or self.DEFAULT_CRON_D_DIR)

        if script_dirs is not None:
            self.script_dirs = [self._resolve_path(d) for d in script_dirs]
        else:
            self.script_dirs = [self._resolve_path(d) for d in self.DEFAULT_SCRIPT_DIRS]

        if spool_dirs is not None:
            self.spool_dirs = [self._resolve_path(d) for d in spool_dirs]
        else:
            self.spool_dirs = [self._resolve_path(d) for d in self.DEFAULT_SPOOL_DIRS]

    def _resolve_path(self, path: Union[str, Path]) -> Path:
        """Resolve a path against root_prefix if configured."""
        p = Path(path)
        if self.root_prefix is not None:
            try:
                if p.is_relative_to(self.root_prefix):
                    return p
            except (ValueError, AttributeError):
                pass
            rel_path = str(p).lstrip("/")
            return self.root_prefix / rel_path
        return p

    def scan(self) -> FindingCollection:
        """Scan cron locations and return collection of security findings."""
        collection = FindingCollection()

        # 1. Inspect system crontab (/etc/crontab)
        self._scan_crontab_file(self.system_crontab, has_user_field=True, collection=collection)

        # 2. Inspect cron.d directory (/etc/cron.d/)
        self._scan_cron_d_directory(self.cron_d_dir, collection=collection)

        # 3. Inspect scheduled script directories (/etc/cron.hourly/, daily, etc.)
        for script_dir in self.script_dirs:
            self._scan_script_directory(script_dir, collection=collection)

        # 4. Inspect user crontab spool directories (/var/spool/cron/crontabs, /var/spool/cron)
        scanned_spool_paths: Set[str] = set()
        for spool_dir in self.spool_dirs:
            self._scan_spool_directory(spool_dir, scanned_spool_paths, collection=collection)

        return collection

    def _scan_crontab_file(
        self,
        file_path: Path,
        has_user_field: bool,
        collection: FindingCollection,
    ) -> None:
        """Safely read and audit a crontab-format file."""
        if not file_path.exists():
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except PermissionError as e:
            collection.add(Finding(
                id="PH-CRON-090",
                category="cron",
                severity=Severity.INFO,
                title="Unreadable cron file (permission denied)",
                description=f"Permission was denied when reading crontab file at {file_path}.",
                evidence=str(e),
                location=str(file_path),
                recommendation="Run PersistHunt with elevated permissions if complete auditing of this file is required."
            ))
            return
        except OSError as e:
            collection.add(Finding(
                id="PH-CRON-090",
                category="cron",
                severity=Severity.INFO,
                title="Error accessing cron file",
                description=f"An unexpected OS error occurred while accessing {file_path}: {e}",
                evidence=str(e),
                location=str(file_path),
                recommendation="Verify filesystem integrity and permissions for this file."
            ))
            return

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            loc = f"{file_path}:{line_no}"

            # Check environment variable definitions (e.g. SHELL=..., LD_PRELOAD=...)
            if self.RE_ENV_VAR.match(line):
                self._analyze_command_indicators(line, loc, line, collection)
                continue

            # Parse schedule entry
            if line.startswith("@"):
                # Special schedule string, e.g. @reboot [user] command
                min_parts = 3 if has_user_field else 2
                parts = line.split(maxsplit=min_parts - 1)
                if len(parts) < min_parts:
                    collection.add(Finding(
                        id="PH-CRON-092",
                        category="cron",
                        severity=Severity.LOW,
                        title="Malformed cron entry",
                        description=f"Crontab line does not contain expected fields for '@' schedule directive.",
                        evidence=line,
                        location=loc,
                        recommendation="Review the crontab syntax and correct the malformed line."
                    ))
                    continue
                command = parts[-1]
            else:
                # Standard 5-field cron schedule
                min_parts = 7 if has_user_field else 6
                parts = line.split(maxsplit=min_parts - 1)
                if len(parts) < min_parts:
                    collection.add(Finding(
                        id="PH-CRON-092",
                        category="cron",
                        severity=Severity.LOW,
                        title="Malformed cron entry",
                        description="Crontab line does not contain standard 5 time fields and command.",
                        evidence=line,
                        location=loc,
                        recommendation="Review the crontab syntax and correct the malformed line."
                    ))
                    continue
                command = parts[-1]

            self._analyze_command_indicators(command, loc, line, collection)

    def _scan_cron_d_directory(self, dir_path: Path, collection: FindingCollection) -> None:
        """Inspect /etc/cron.d drop-in directory."""
        if not dir_path.exists():
            return

        try:
            entries = list(os.scandir(dir_path))
        except PermissionError as e:
            collection.add(Finding(
                id="PH-CRON-090",
                category="cron",
                severity=Severity.INFO,
                title="Unreadable cron directory (permission denied)",
                description=f"Permission was denied when listing {dir_path}.",
                evidence=str(e),
                location=str(dir_path),
                recommendation="Run PersistHunt with elevated permissions if auditing of this directory is required."
            ))
            return
        except OSError:
            return

        for entry in entries:
            entry_path = Path(entry.path)
            # Check for broken symlink
            if entry.is_symlink() and not entry_path.exists():
                collection.add(Finding(
                    id="PH-CRON-091",
                    category="cron",
                    severity=Severity.LOW,
                    title="Broken symlink in cron directory",
                    description=f"Symlink at {entry_path} points to a non-existent target.",
                    evidence=f"Symlink target: {os.readlink(entry.path)}",
                    location=str(entry_path),
                    recommendation="Verify why the target was removed and remove or fix the broken symlink."
                ))
                continue

            # Check for hidden files
            if entry.name.startswith("."):
                collection.add(Finding(
                    id="PH-CRON-006",
                    category="cron",
                    severity=Severity.MEDIUM,
                    title="Suspicious hidden file in cron directory",
                    description=f"Hidden file '{entry.name}' detected in cron directory {dir_path}. Cron typically ignores dotfiles, but hidden files in system cron directories are anomalous.",
                    evidence=f"Filename: {entry.name}",
                    location=str(entry_path),
                    recommendation="Investigate the origin and purpose of this hidden file."
                ))

            if entry.is_file():
                self._scan_crontab_file(entry_path, has_user_field=True, collection=collection)

    def _scan_script_directory(self, dir_path: Path, collection: FindingCollection) -> None:
        """Inspect scheduled script directories (cron.hourly, cron.daily, etc.)."""
        if not dir_path.exists():
            return

        try:
            entries = list(os.scandir(dir_path))
        except PermissionError as e:
            collection.add(Finding(
                id="PH-CRON-090",
                category="cron",
                severity=Severity.INFO,
                title="Unreadable cron script directory (permission denied)",
                description=f"Permission was denied when listing {dir_path}.",
                evidence=str(e),
                location=str(dir_path),
                recommendation="Run PersistHunt with elevated permissions if auditing of this directory is required."
            ))
            return
        except OSError:
            return

        for entry in entries:
            entry_path = Path(entry.path)
            # Check for broken symlink
            if entry.is_symlink() and not entry_path.exists():
                collection.add(Finding(
                    id="PH-CRON-091",
                    category="cron",
                    severity=Severity.LOW,
                    title="Broken symlink in cron directory",
                    description=f"Symlink at {entry_path} points to a non-existent target.",
                    evidence=f"Symlink target: {os.readlink(entry.path)}",
                    location=str(entry_path),
                    recommendation="Verify why the target was removed and remove or fix the broken symlink."
                ))
                continue

            # Check for hidden files
            if entry.name.startswith("."):
                collection.add(Finding(
                    id="PH-CRON-006",
                    category="cron",
                    severity=Severity.MEDIUM,
                    title="Suspicious hidden file in cron directory",
                    description=f"Hidden file '{entry.name}' detected in cron directory {dir_path}.",
                    evidence=f"Filename: {entry.name}",
                    location=str(entry_path),
                    recommendation="Investigate the origin and purpose of this hidden file."
                ))

            if not entry.is_file():
                continue

            # Audit script contents line-by-line safely
            try:
                with open(entry_path, "r", encoding="utf-8", errors="replace") as f:
                    # Check first 1KB for binary content
                    header = f.read(1024)
                    if "\x00" in header:
                        # Binary executable in cron directory
                        collection.add(Finding(
                            id="PH-CRON-006",
                            category="cron",
                            severity=Severity.MEDIUM,
                            title="Binary executable in cron script directory",
                            description=f"A binary executable was detected in scheduled script directory {dir_path}.",
                            evidence=f"Binary file: {entry.name}",
                            location=str(entry_path),
                            recommendation="Ensure binary files in scheduled script directories are authorized distribution packages."
                        ))
                        continue

                    f.seek(0)
                    for line_no, raw_line in enumerate(f, start=1):
                        if line_no > 5000:
                            break  # Safety ceiling
                        line = raw_line.strip()
                        if not line:
                            continue
                        # Skip pure comments unless they look like shebang referencing temp/dev
                        if line.startswith("#"):
                            if line.startswith("#!") and ("tmp" in line or "dev" in line):
                                self._analyze_command_indicators(line, f"{entry_path}:{line_no}", line, collection)
                            continue
                        self._analyze_command_indicators(line, f"{entry_path}:{line_no}", line, collection)
            except PermissionError as e:
                collection.add(Finding(
                    id="PH-CRON-090",
                    category="cron",
                    severity=Severity.INFO,
                    title="Unreadable cron script (permission denied)",
                    description=f"Permission was denied when reading script at {entry_path}.",
                    evidence=str(e),
                    location=str(entry_path),
                    recommendation="Run PersistHunt with elevated permissions if complete auditing is required."
                ))
            except OSError:
                continue

    def _scan_spool_directory(
        self,
        spool_path: Path,
        scanned_paths: Set[str],
        collection: FindingCollection,
    ) -> None:
        """Inspect user crontab spool directory."""
        if not spool_path.exists():
            return

        canonical = str(spool_path.resolve()) if spool_path.is_symlink() or spool_path.exists() else str(spool_path)
        if canonical in scanned_paths:
            return
        scanned_paths.add(canonical)

        try:
            entries = list(os.scandir(spool_path))
        except PermissionError as e:
            collection.add(Finding(
                id="PH-CRON-090",
                category="cron",
                severity=Severity.INFO,
                title="Unreadable user crontab spool (permission denied)",
                description=f"Permission was denied when accessing user crontab directory at {spool_path}. Inspecting user crontabs typically requires elevated privileges.",
                evidence=str(e),
                location=str(spool_path),
                recommendation="Run PersistHunt with elevated permissions (e.g. root) to audit restricted user crontabs."
            ))
            return
        except OSError:
            return

        for entry in entries:
            # Skip subdirectories (e.g. 'crontabs' inside '/var/spool/cron')
            if entry.is_dir():
                continue
            if entry.is_file():
                # User crontabs do not have the user field in the line format
                self._scan_crontab_file(Path(entry.path), has_user_field=False, collection=collection)

    def _analyze_command_indicators(
        self,
        command: str,
        location: str,
        raw_evidence: str,
        collection: FindingCollection,
    ) -> None:
        """Analyze a command string for persistence indicators and emit findings."""
        fired_ids: Set[str] = set()

        # 1. Reverse shell / Raw network socket indicators
        if self.RE_SOCKET_DEV.search(command):
            fired_ids.add("PH-CRON-001")
            collection.add(Finding(
                id="PH-CRON-001",
                category="cron",
                severity=Severity.HIGH,
                title="Suspicious network socket redirection in cron entry",
                description="Command references '/dev/tcp' or '/dev/udp' socket paths, commonly associated with reverse shell communication.",
                evidence=raw_evidence,
                location=location,
                recommendation="Inspect the cron entry immediately and verify if outbound network connections are authorized."
            ))
        elif self.RE_NETCAT.search(command):
            fired_ids.add("PH-CRON-001")
            collection.add(Finding(
                id="PH-CRON-001",
                category="cron",
                severity=Severity.HIGH,
                title="Suspicious interactive network utility in cron entry",
                description="Command references network tools (nc, ncat, netcat, socat) frequently leveraged for interactive shells or unauthorized data exfiltration.",
                evidence=raw_evidence,
                location=location,
                recommendation="Verify whether interactive networking utilities are expected in this scheduled job."
            ))
        elif self.RE_MKFIFO.search(command):
            fired_ids.add("PH-CRON-001")
            collection.add(Finding(
                id="PH-CRON-001",
                category="cron",
                severity=Severity.HIGH,
                title="Named pipe utility (mkfifo) in cron entry",
                description="Command invokes 'mkfifo', often used to create FIFO pipes for bidirectional reverse shell connections.",
                evidence=raw_evidence,
                location=location,
                recommendation="Audit the command pipeline and terminate any unauthorized background processes."
            ))

        # 2. Remote download utilities & piped execution
        if self.RE_DOWNLOAD_PIPE.search(command):
            fired_ids.add("PH-CRON-002")
            collection.add(Finding(
                id="PH-CRON-002",
                category="cron",
                severity=Severity.HIGH,
                title="Remote download piped directly into shell/interpreter",
                description="Command downloads remote resources and pipes them directly into a shell or interpreter, bypassing disk inspection and file integrity controls.",
                evidence=raw_evidence,
                location=location,
                recommendation="Verify the download source URL and terminate any unauthorized scheduled execution."
            ))
        elif self.RE_DOWNLOAD_TOOL.search(command) and "PH-CRON-002" not in fired_ids:
            fired_ids.add("PH-CRON-002")
            collection.add(Finding(
                id="PH-CRON-002",
                category="cron",
                severity=Severity.MEDIUM,
                title="Remote download utility in cron entry",
                description="Command invokes a network retrieval utility (curl or wget). While sometimes used for updates, scheduled remote downloads present persistence and tampering risks.",
                evidence=raw_evidence,
                location=location,
                recommendation="Review the remote endpoint and ensure automated network downloads in cron are authorized."
            ))

        # 3. Temporary / World-writable directory execution or references
        if self.RE_TEMP_DIRS.search(command):
            fired_ids.add("PH-CRON-003")
            collection.add(Finding(
                id="PH-CRON-003",
                category="cron",
                severity=Severity.MEDIUM,
                title="Reference to temporary/writable directory in cron entry",
                description="Command references or executes binaries/scripts from temporary directories (/tmp, /var/tmp, /dev/shm). These directories are world-writable and frequently used to stage unauthorized payloads.",
                evidence=raw_evidence,
                location=location,
                recommendation="Relocate scripts or binaries to protected system directories (e.g. /usr/local/bin) owned by root."
            ))

        # 4. Inline code execution
        if self.RE_INLINE_INTERP.search(command):
            fired_ids.add("PH-CRON-004")
            collection.add(Finding(
                id="PH-CRON-004",
                category="cron",
                severity=Severity.MEDIUM,
                title="Inline interpreter command execution in cron entry",
                description="Command executes inline script logic using interpreter flags (-c or -e). Inline execution can obscure malicious behavior and avoids creating trackable script files.",
                evidence=raw_evidence,
                location=location,
                recommendation="Inspect the inline code and consider placing verified administrative logic into dedicated, audited scripts."
            ))

        # 5. Encoded payload execution
        if self.RE_BASE64_DECODE.search(command):
            fired_ids.add("PH-CRON-005")
            collection.add(Finding(
                id="PH-CRON-005",
                category="cron",
                severity=Severity.HIGH,
                title="Encoded payload decoding in cron entry",
                description="Command decodes base64 data, an indicator commonly used to obfuscate commands, scripts, or reverse shells.",
                evidence=raw_evidence,
                location=location,
                recommendation="Decode and review the base64 content to ensure it does not execute unauthorized commands."
            ))
