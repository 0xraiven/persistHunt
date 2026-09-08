import os
import re
from pathlib import Path
from typing import Optional, Union, Iterable, List, Set
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector

class ShellDetector(BaseDetector):
    """Detector for Linux shell startup persistence mechanisms.

    Audits system-wide shell startup configurations (/etc/profile,
    /etc/profile.d, /etc/bash.bashrc, /etc/zsh) and user-level startup files
    (~/.bashrc, ~/.profile, ~/.bash_profile, ~/.zshrc) for suspicious persistence
    and execution indicators.

    Adheres to strict read-only auditing safety: never executes, sources, or
    modifies shell startup files, treating all contents as untrusted text.
    """

    name: str = "Shell Startup Persistence Detector"
    detector_id: str = "shell"

    DEFAULT_SYSTEM_FILES = [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/bashrc",
        "/etc/zsh/zprofile",
        "/etc/zsh/zshrc",
        "/etc/zshrc",
        "/etc/environment",
    ]

    DEFAULT_SYSTEM_DIRS = [
        "/etc/profile.d",
    ]

    USER_STARTUP_FILENAMES = [
        ".bashrc",
        ".profile",
        ".bash_profile",
        ".bash_login",
        ".zshrc",
        ".zprofile",
        ".bash_aliases",
        ".bash_logout",
        ".zlogout",
        ".kshrc",
    ]

    # Whitelist of standard hidden tool directories commonly sourced in startup scripts
    BENIGN_HIDDEN_DIRS = {
        ".cargo",
        ".rustup",
        ".nvm",
        ".rvm",
        ".local",
        ".config",
        ".gnupg",
        ".ssh",
        ".oh-my-zsh",
        ".pyenv",
        ".nodenv",
        ".rbenv",
        ".sdkman",
        ".fzf",
        ".dircolors",
    }

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
    RE_HIJACK_ALIAS = re.compile(
        r"^\s*alias\s+(sudo|su|ssh|scp|login|passwd)\s*=", re.IGNORECASE
    )
    RE_HIDDEN_PATH = re.compile(r"(?:/|^)(\.[a-zA-Z0-9_-]+)/(\S+)")

    def __init__(
        self,
        root_prefix: Optional[Union[str, Path]] = None,
        system_files: Optional[Iterable[Union[str, Path]]] = None,
        system_dirs: Optional[Iterable[Union[str, Path]]] = None,
        home_dir: Optional[Union[str, Path]] = None,
        root_home_dir: Optional[Union[str, Path]] = None,
        custom_files: Optional[Iterable[Union[str, Path]]] = None,
    ):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.root_prefix = Path(root_prefix) if root_prefix else None
        self._explicit_home_dir = home_dir is not None

        if system_files is not None:
            self.system_files = [self._resolve_path(f) for f in system_files]
        else:
            self.system_files = [self._resolve_path(f) for f in self.DEFAULT_SYSTEM_FILES]

        if system_dirs is not None:
            self.system_dirs = [self._resolve_path(d) for d in system_dirs]
        else:
            self.system_dirs = [self._resolve_path(d) for d in self.DEFAULT_SYSTEM_DIRS]

        self.home_dir = self._resolve_path(home_dir or "/home")
        self.root_home_dir = self._resolve_path(root_home_dir or "/root")

        self.custom_files = (
            [self._resolve_path(p) for p in custom_files]
            if custom_files is not None
            else []
        )

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
        """Scan shell startup locations and return a FindingCollection."""
        collection = FindingCollection()
        scanned_files: Set[str] = set()

        # 1. Audit system-wide startup files
        for s_file in self.system_files:
            self._audit_file_if_exists(s_file, scanned_files, collection)

        # 2. Audit system-wide profile directories (/etc/profile.d)
        for s_dir in self.system_dirs:
            self._scan_profile_directory(s_dir, scanned_files, collection)

        # 3. Audit root user startup files
        self._scan_user_home(self.root_home_dir, scanned_files, collection)

        # 4. Audit /home/* user startup files
        if self.home_dir.exists():
            try:
                user_dirs = list(os.scandir(self.home_dir))
            except PermissionError as e:
                collection.add(Finding(
                    id="PH-SHELL-090",
                    category="shell",
                    severity=Severity.INFO,
                    title="Unreadable home directory (permission denied)",
                    description=f"Permission was denied when listing {self.home_dir}.",
                    evidence=str(e),
                    location=str(self.home_dir),
                    recommendation="Run PersistHunt with elevated permissions if complete user auditing is required."
                ))
                user_dirs = []
            except OSError:
                user_dirs = []

            for u_entry in user_dirs:
                if u_entry.is_dir():
                    self._scan_user_home(Path(u_entry.path), scanned_files, collection)

        # 5. Audit current user home if running without root_prefix and home_dir was not explicitly configured
        if self.root_prefix is None and not self._explicit_home_dir:
            current_home = Path.home()
            self._scan_user_home(current_home, scanned_files, collection)

        # 6. Audit any explicitly configured custom files
        for c_file in self.custom_files:
            self._audit_file_if_exists(c_file, scanned_files, collection)

        return collection

    def _scan_profile_directory(
        self, dir_path: Path, scanned_files: Set[str], collection: FindingCollection
    ) -> None:
        """Inspect a profile drop-in directory such as /etc/profile.d."""
        if not dir_path.exists():
            return

        try:
            entries = list(os.scandir(dir_path))
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SHELL-090",
                category="shell",
                severity=Severity.INFO,
                title="Unreadable profile directory (permission denied)",
                description=f"Permission was denied when listing {dir_path}.",
                evidence=str(e),
                location=str(dir_path),
                recommendation="Run PersistHunt with elevated permissions if complete auditing is required."
            ))
            return
        except OSError:
            return

        for entry in entries:
            entry_path = Path(entry.path)
            if entry.is_symlink() and not entry_path.exists():
                collection.add(Finding(
                    id="PH-SHELL-091",
                    category="shell",
                    severity=Severity.LOW,
                    title="Broken symlink in shell startup directory",
                    description=f"Symlink at {entry_path} points to a missing target.",
                    evidence=f"Symlink target: {os.readlink(entry.path)}",
                    location=str(entry_path),
                    recommendation="Remove or repair dangling symlinks in shell startup directory."
                ))
                continue

            if entry.is_file():
                self._audit_file_if_exists(entry_path, scanned_files, collection)

    def _scan_user_home(
        self, home_path: Path, scanned_files: Set[str], collection: FindingCollection
    ) -> None:
        """Inspect shell startup files inside a user home directory."""
        if not home_path.exists():
            return

        for fname in self.USER_STARTUP_FILENAMES:
            startup_file = home_path / fname
            self._audit_file_if_exists(startup_file, scanned_files, collection)

    def _audit_file_if_exists(
        self, file_path: Path, scanned_files: Set[str], collection: FindingCollection
    ) -> None:
        """Audit a single shell startup file if it exists and has not been scanned."""
        if not file_path.exists():
            return

        canonical = str(file_path.resolve()) if file_path.exists() else str(file_path)
        if canonical in scanned_files:
            return
        scanned_files.add(canonical)

        # Check permissions
        self._check_file_permissions(file_path, collection)

        # Read file contents safely
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                # Check for binary content in the first 1KB
                header = f.read(1024)
                if "\x00" in header:
                    # Binary file in startup location
                    collection.add(Finding(
                        id="PH-SHELL-004",
                        category="shell",
                        severity=Severity.HIGH,
                        title="Binary executable found in shell startup location",
                        description=f"Startup file {file_path} contains binary content. Shell startup files must be plaintext shell scripts.",
                        evidence=f"File: {file_path.name}",
                        location=str(file_path),
                        recommendation="Investigate why a binary file is placed in this shell initialization path."
                    ))
                    return

                f.seek(0)
                lines = f.readlines()
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SHELL-090",
                category="shell",
                severity=Severity.INFO,
                title="Unreadable shell startup file (permission denied)",
                description=f"Permission was denied when reading {file_path}.",
                evidence=str(e),
                location=str(file_path),
                recommendation="Run PersistHunt with elevated permissions if complete startup file auditing is required."
            ))
            return
        except OSError as e:
            collection.add(Finding(
                id="PH-SHELL-090",
                category="shell",
                severity=Severity.INFO,
                title="Error reading shell startup file",
                description=f"OS error accessing {file_path}: {e}",
                evidence=str(e),
                location=str(file_path),
                recommendation="Verify filesystem integrity for this file."
            ))
            return

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            # Skip comments unless shebang contains suspicious location
            if line.startswith("#"):
                if line.startswith("#!") and ("tmp" in line or "dev" in line):
                    self._analyze_line(line, f"{file_path}:{line_no}", line, collection)
                continue

            loc = f"{file_path}:{line_no}"
            self._analyze_line(line, loc, line, collection)

    def _check_file_permissions(self, file_path: Path, collection: FindingCollection) -> None:
        """Check for dangerous world-writable permissions on startup files."""
        try:
            st = file_path.stat()
            if (st.st_mode & 0o002) != 0:
                collection.add(Finding(
                    id="PH-SHELL-008",
                    category="shell",
                    severity=Severity.HIGH,
                    title="Insecure world-writable shell startup file",
                    description=f"The shell startup file at {file_path} is world-writable ({oct(st.st_mode & 0o777)}). Any local user can append malicious commands to be executed on login.",
                    evidence=f"Permissions: {oct(st.st_mode & 0o777)}",
                    location=str(file_path),
                    recommendation=f"Restrict write permissions immediately: chmod 644 {file_path}."
                ))
        except (OSError, PermissionError):
            pass

    def _analyze_line(
        self, line: str, location: str, raw_evidence: str, collection: FindingCollection
    ) -> None:
        """Analyze a single line from a shell startup script for indicators."""
        evidence = raw_evidence[:200] + ("..." if len(raw_evidence) > 200 else "")
        fired_ids: Set[str] = set()

        # 1. Reverse shell / Raw network socket indicators
        if self.RE_SOCKET_DEV.search(line):
            fired_ids.add("PH-SHELL-001")
            collection.add(Finding(
                id="PH-SHELL-001",
                category="shell",
                severity=Severity.HIGH,
                title="Suspicious network socket redirection in shell startup file",
                description="Line references '/dev/tcp' or '/dev/udp' socket paths, commonly associated with reverse shell communication.",
                evidence=evidence,
                location=location,
                recommendation="Inspect startup script line immediately and verify if outbound raw network connections are authorized."
            ))
        elif self.RE_NETCAT.search(line):
            fired_ids.add("PH-SHELL-001")
            collection.add(Finding(
                id="PH-SHELL-001",
                category="shell",
                severity=Severity.HIGH,
                title="Suspicious interactive network utility in shell startup file",
                description="Line references interactive network tools (nc, ncat, netcat, socat) commonly used for reverse shell persistence or unauthorized exfiltration.",
                evidence=evidence,
                location=location,
                recommendation="Verify whether interactive networking utilities are expected in this startup script."
            ))
        elif self.RE_MKFIFO.search(line):
            fired_ids.add("PH-SHELL-001")
            collection.add(Finding(
                id="PH-SHELL-001",
                category="shell",
                severity=Severity.HIGH,
                title="Named pipe utility (mkfifo) in shell startup file",
                description="Line invokes 'mkfifo', often used to create FIFO pipes for bidirectional shell pipelines.",
                evidence=evidence,
                location=location,
                recommendation="Audit the command pipeline and remove unauthorized startup commands."
            ))

        # 2. Remote download and piped execution
        if self.RE_DOWNLOAD_PIPE.search(line):
            fired_ids.add("PH-SHELL-002")
            collection.add(Finding(
                id="PH-SHELL-002",
                category="shell",
                severity=Severity.HIGH,
                title="Remote download piped directly into shell in startup script",
                description="Line downloads remote code via curl/wget and pipes it directly into a shell or interpreter.",
                evidence=evidence,
                location=location,
                recommendation="Verify the remote endpoint immediately and eliminate unverified remote downloads from startup files."
            ))
        elif self.RE_DOWNLOAD_TOOL.search(line) and "PH-SHELL-002" not in fired_ids:
            fired_ids.add("PH-SHELL-002")
            collection.add(Finding(
                id="PH-SHELL-002",
                category="shell",
                severity=Severity.MEDIUM,
                title="Remote download utility in shell startup file",
                description="Line invokes a network download tool (curl/wget). Fetching remote resources during shell startup presents persistence and hijacking risks.",
                evidence=evidence,
                location=location,
                recommendation="Review the destination endpoint and ensure automated downloads on shell login are authorized."
            ))

        # 3. Temporary / World-writable directory execution or reference
        if self.RE_TEMP_DIRS.search(line):
            fired_ids.add("PH-SHELL-003")
            collection.add(Finding(
                id="PH-SHELL-003",
                category="shell",
                severity=Severity.HIGH,
                title="Execution or reference to temporary directory in shell startup",
                description="Line references or executes scripts/binaries from world-writable directories (/tmp, /var/tmp, /dev/shm). Attackers frequently stage persistence payloads in these locations.",
                evidence=evidence,
                location=location,
                recommendation="Relocate scripts or binaries to protected system directories owned by root."
            ))

        # 4. Hidden directory execution
        hidden_match = self.RE_HIDDEN_PATH.search(line)
        if hidden_match:
            hidden_dir_name = hidden_match.group(1)
            if hidden_dir_name not in self.BENIGN_HIDDEN_DIRS:
                fired_ids.add("PH-SHELL-004")
                collection.add(Finding(
                    id="PH-SHELL-004",
                    category="shell",
                    severity=Severity.MEDIUM,
                    title="Execution from anomalous hidden directory path in startup script",
                    description=f"Line references or executes files from an anomalous hidden directory (.{hidden_dir_name}). Stealth persistence is often concealed in non-standard hidden folders.",
                    evidence=evidence,
                    location=location,
                    recommendation="Inspect the hidden directory and confirm whether its contents are authorized."
                ))

        # 5. Inline interpreter execution
        if self.RE_INLINE_INTERP.search(line):
            fired_ids.add("PH-SHELL-005")
            collection.add(Finding(
                id="PH-SHELL-005",
                category="shell",
                severity=Severity.MEDIUM,
                title="Inline interpreter command execution in shell startup file",
                description="Line uses inline script execution (-c or -e) to run code directly inside the startup file.",
                evidence=evidence,
                location=location,
                recommendation="Inspect the inline code and migrate complex logic to an audited script file."
            ))

        # 6. Encoded payload decoding
        if self.RE_BASE64_DECODE.search(line):
            fired_ids.add("PH-SHELL-006")
            collection.add(Finding(
                id="PH-SHELL-006",
                category="shell",
                severity=Severity.HIGH,
                title="Encoded payload decoding in shell startup file",
                description="Line decodes base64 data, an indicator commonly used to obfuscate commands, scripts, or reverse shells.",
                evidence=evidence,
                location=location,
                recommendation="Decode and review the base64 content to verify its intent."
            ))

        # 7. Hijacked aliases (sudo, su, ssh)
        if self.RE_HIJACK_ALIAS.search(line):
            fired_ids.add("PH-SHELL-007")
            collection.add(Finding(
                id="PH-SHELL-007",
                category="shell",
                severity=Severity.HIGH,
                title="Privilege or authentication utility alias defined in shell startup",
                description="Line defines an alias overriding a critical authentication or privilege utility (sudo, su, ssh). This technique is frequently used for credential theft or command interception.",
                evidence=evidence,
                location=location,
                recommendation="Audit the alias definition to ensure it does not intercept or log user credentials."
            ))
