import os
import re
from pathlib import Path
from typing import Optional, Union, Iterable, List, Set, Dict, Tuple
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector, safe_read_lines

class SystemdDetector(BaseDetector):
    """Detector for Linux systemd persistence mechanisms.

    Audits system unit directories (/etc/systemd/system, /run/systemd/system,
    /usr/lib/systemd/system), user unit directories (~/.config/systemd/user,
    /etc/systemd/user), drop-in configurations, and associated symlinks for
    suspicious persistence indicators.

    Adheres to strict read-only auditing safety: never modifies unit files,
    never executes service commands, and never interacts with the systemd daemon.
    """

    name: str = "Systemd Persistence Detector"
    detector_id: str = "systemd"

    DEFAULT_SYSTEM_DIRS = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ]

    DEFAULT_USER_DIRS = [
        "/etc/systemd/user",
        "/usr/lib/systemd/user",
    ]

    EXEC_DIRECTIVES = {
        "execstart",
        "execstartpre",
        "execstartpost",
        "execreload",
        "execstop",
        "execstoppost",
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
    RE_HIDDEN_DIR = re.compile(r"/\.[a-zA-Z0-9_-]+(/|\S*)")
    RE_INLINE_INTERP = re.compile(
        r"(\b(python[0-9.]*|perl|ruby)\s+(-c|-e)\b|\b(bash|sh|zsh|dash)\s+-c\b)",
        re.IGNORECASE,
    )
    RE_HOME_EXEC = re.compile(r"^/home/[^/]+/\S+")

    def __init__(
        self,
        root_prefix: Optional[Union[str, Path]] = None,
        system_dirs: Optional[Iterable[Union[str, Path]]] = None,
        user_dirs: Optional[Iterable[Union[str, Path]]] = None,
        custom_unit_paths: Optional[Iterable[Union[str, Path]]] = None,
    ):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.root_prefix = Path(root_prefix) if root_prefix else None

        if system_dirs is not None:
            self.system_dirs = [self._resolve_path(d) for d in system_dirs]
        else:
            self.system_dirs = [self._resolve_path(d) for d in self.DEFAULT_SYSTEM_DIRS]

        if user_dirs is not None:
            self.user_dirs = [self._resolve_path(d) for d in user_dirs]
        else:
            self.user_dirs = [self._resolve_path(d) for d in self.DEFAULT_USER_DIRS]
            # If no root_prefix is configured, also inspect current user config
            if self.root_prefix is None:
                user_config = Path.home() / ".config" / "systemd" / "user"
                self.user_dirs.append(user_config)
            else:
                # When testing with root_prefix, check for home/*/.config/systemd/user
                home_base = self.root_prefix / "home"
                try:
                    home_exists = home_base.exists()
                except (OSError, PermissionError):
                    home_exists = False
                if home_exists:
                    try:
                        for u_home in home_base.iterdir():
                            user_cfg = u_home / ".config" / "systemd" / "user"
                            self.user_dirs.append(user_cfg)
                    except (OSError, PermissionError):
                        pass

        self.custom_unit_paths = (
            [self._resolve_path(p) for p in custom_unit_paths]
            if custom_unit_paths is not None
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
        """Scan systemd unit locations and return a FindingCollection."""
        collection = FindingCollection()
        scanned_files: Set[str] = set()

        # 1. Scan system unit directories
        for s_dir in self.system_dirs:
            self._scan_unit_directory(s_dir, is_user_unit=False, scanned_files=scanned_files, collection=collection)

        # 2. Scan user unit directories
        for u_dir in self.user_dirs:
            self._scan_unit_directory(u_dir, is_user_unit=True, scanned_files=scanned_files, collection=collection)

        # 3. Scan any explicitly configured unit paths
        for c_path in self.custom_unit_paths:
            try:
                c_exists = c_path.exists()
            except (OSError, PermissionError):
                c_exists = False
            if c_exists and str(c_path) not in scanned_files:
                scanned_files.add(str(c_path))
                self._audit_unit_file(c_path, is_user_unit=False, collection=collection)

        return collection

    def _scan_unit_directory(
        self,
        dir_path: Path,
        is_user_unit: bool,
        scanned_files: Set[str],
        collection: FindingCollection,
    ) -> None:
        """Inspect a directory containing systemd unit files or drop-ins."""
        try:
            if not dir_path.exists():
                return
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SYSTEMD-090",
                category="systemd",
                severity=Severity.INFO,
                title="Unreadable systemd directory (permission denied)",
                description=f"Permission was denied when listing {dir_path}.",
                evidence=str(e),
                location=str(dir_path),
                recommendation="Run PersistHunt with elevated permissions if complete auditing is required."
            ))
            return
        except OSError:
            return

        try:
            entries = list(os.scandir(dir_path))
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SYSTEMD-090",
                category="systemd",
                severity=Severity.INFO,
                title="Unreadable systemd directory (permission denied)",
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

            # Check for broken symlink
            is_broken = False
            if entry.is_symlink():
                try:
                    is_broken = not entry_path.exists()
                except (OSError, PermissionError):
                    is_broken = False
            if is_broken:
                collection.add(Finding(
                    id="PH-SYSTEMD-091",
                    category="systemd",
                    severity=Severity.LOW,
                    title="Broken symlink in systemd directory",
                    description=f"Symlink at {entry_path} points to non-existent target.",
                    evidence=f"Symlink target: {os.readlink(entry.path)}",
                    location=str(entry_path),
                    recommendation="Verify why the target unit was removed and clean up the dangling symlink."
                ))
                continue

            # Check for hidden unit file or directory
            if entry.name.startswith("."):
                collection.add(Finding(
                    id="PH-SYSTEMD-004",
                    category="systemd",
                    severity=Severity.MEDIUM,
                    title="Hidden file or directory in systemd directory",
                    description=f"Hidden entry '{entry.name}' detected in systemd directory {dir_path}.",
                    evidence=f"Name: {entry.name}",
                    location=str(entry_path),
                    recommendation="Investigate why a hidden file is stored in a systemd unit directory."
                ))

            # If directory is a wants/requires directory (e.g. multi-user.target.wants)
            # or a drop-in directory (e.g. foo.service.d)
            if entry.is_dir():
                if entry.name.endswith(".wants") or entry.name.endswith(".requires") or entry.name.endswith(".d"):
                    self._scan_unit_directory(entry_path, is_user_unit, scanned_files, collection)
                continue

            # If regular unit file (.service, .timer, .socket, .path, .conf)
            if entry.is_file() and any(
                entry.name.endswith(ext)
                for ext in (".service", ".timer", ".socket", ".path", ".conf", ".target")
            ):
                try:
                    canonical_path = str(entry_path.resolve())
                except (OSError, PermissionError):
                    canonical_path = str(entry_path)
                if canonical_path in scanned_files:
                    continue
                scanned_files.add(canonical_path)

                # Check insecure file permissions (world-writable) for system units
                if not is_user_unit:
                    self._check_file_permissions(entry_path, collection)

                self._audit_unit_file(entry_path, is_user_unit, collection)

    def _check_file_permissions(self, file_path: Path, collection: FindingCollection) -> None:
        """Check for dangerously loose permissions on unit files."""
        try:
            st = file_path.stat()
            if (st.st_mode & 0o002) != 0:
                collection.add(Finding(
                    id="PH-SYSTEMD-006",
                    category="systemd",
                    severity=Severity.HIGH,
                    title="Insecure world-writable systemd unit file",
                    description=f"The systemd unit file at {file_path} is world-writable, allowing any local user to modify service execution.",
                    evidence=f"Permissions: {oct(st.st_mode & 0o777)}",
                    location=str(file_path),
                    recommendation="Immediately restrict file permissions to root-only (chmod 644 or 600)."
                ))
        except (OSError, PermissionError):
            pass

    def _audit_unit_file(
        self,
        file_path: Path,
        is_user_unit: bool,
        collection: FindingCollection,
    ) -> None:
        """Parse and audit a single systemd unit file."""
        try:
            lines = safe_read_lines(file_path)
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SYSTEMD-090",
                category="systemd",
                severity=Severity.INFO,
                title="Unreadable unit file (permission denied)",
                description=f"Permission was denied when reading unit file at {file_path}.",
                evidence=str(e),
                location=str(file_path),
                recommendation="Run PersistHunt with elevated permissions if auditing of this file is required."
            ))
            return
        except OSError as e:
            collection.add(Finding(
                id="PH-SYSTEMD-090",
                category="systemd",
                severity=Severity.INFO,
                title="Error accessing unit file",
                description=f"An unexpected OS error occurred while accessing {file_path}: {e}",
                evidence=str(e),
                location=str(file_path),
                recommendation="Verify filesystem integrity for this unit file."
            ))
            return

        # Parse sections and directives with line continuation
        directives = self._parse_unit_directives(lines, file_path, collection)

        # Inspect directives
        for section, key, value, line_no in directives:
            key_lower = key.lower()

            if key_lower in self.EXEC_DIRECTIVES:
                loc = f"{file_path}:{line_no}"
                self._analyze_exec_directive(
                    directive_key=key,
                    raw_value=value,
                    location=loc,
                    is_user_unit=is_user_unit,
                    collection=collection,
                )

    def _parse_unit_directives(
        self,
        lines: List[str],
        file_path: Path,
        collection: FindingCollection,
    ) -> List[Tuple[str, str, str, int]]:
        """Parse lines into (section, key, value, line_no) tuples safely."""
        directives: List[Tuple[str, str, str, int]] = []
        current_section = ""
        current_key = ""
        current_val_parts: List[str] = []
        start_line_no = 0
        in_continuation = False

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip empty lines and comments
            if not in_continuation and (not line or line.startswith("#") or line.startswith(";")):
                continue

            # Section header: [Service], [Unit], etc.
            if not in_continuation and line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip()
                continue

            # Line continuation handling
            if in_continuation:
                if line.endswith("\\"):
                    current_val_parts.append(line[:-1].strip())
                else:
                    current_val_parts.append(line)
                    directives.append(
                        (current_section, current_key, " ".join(current_val_parts), start_line_no)
                    )
                    in_continuation = False
                    current_key = ""
                    current_val_parts = []
                continue

            # Key=Value directive
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()

                if val.endswith("\\"):
                    in_continuation = True
                    current_key = key
                    start_line_no = line_no
                    current_val_parts = [val[:-1].strip()]
                else:
                    directives.append((current_section, key, val, line_no))
            else:
                # Malformed non-empty, non-comment line outside continuation
                if line:
                    collection.add(Finding(
                        id="PH-SYSTEMD-092",
                        category="systemd",
                        severity=Severity.LOW,
                        title="Malformed systemd unit directive",
                        description=f"Line in unit file does not follow 'Key=Value' format.",
                        evidence=line,
                        location=f"{file_path}:{line_no}",
                        recommendation="Review unit file syntax for formatting errors."
                    ))

        # Handle unfinished continuation at EOF
        if in_continuation and current_key:
            directives.append(
                (current_section, current_key, " ".join(current_val_parts), start_line_no)
            )

        return directives

    def _analyze_exec_directive(
        self,
        directive_key: str,
        raw_value: str,
        location: str,
        is_user_unit: bool,
        collection: FindingCollection,
    ) -> None:
        """Analyze an Exec* directive for malicious or suspicious indicators."""
        if not raw_value:
            return

        # Strip systemd execution prefixes:
        # '-' (ignore failure), '@' (argv[0]), '+' (full privilege),
        # '!' (no privilege dropping), '!!' (ambient caps), ':' (no env subst)
        cleaned = raw_value.lstrip("-@+!:")
        tokens = cleaned.split()
        if not tokens:
            return

        exe_path = tokens[0]

        # 1. Reverse shell / raw network socket indicators
        if self.RE_SOCKET_DEV.search(cleaned):
            collection.add(Finding(
                id="PH-SYSTEMD-001",
                category="systemd",
                severity=Severity.HIGH,
                title="Suspicious network socket redirection in systemd unit",
                description=f"{directive_key} references '/dev/tcp' or '/dev/udp' socket paths, commonly associated with reverse shell communication.",
                evidence=raw_value,
                location=location,
                recommendation="Inspect unit configuration immediately and verify if outbound raw network connections are authorized."
            ))
        elif self.RE_NETCAT.search(cleaned):
            collection.add(Finding(
                id="PH-SYSTEMD-001",
                category="systemd",
                severity=Severity.HIGH,
                title="Suspicious interactive network utility in systemd unit",
                description=f"{directive_key} references interactive network tools (nc, ncat, netcat, socat) commonly used for reverse shell persistence or unauthorized exfiltration.",
                evidence=raw_value,
                location=location,
                recommendation="Verify whether interactive networking utilities are expected in this service."
            ))
        elif self.RE_MKFIFO.search(cleaned):
            collection.add(Finding(
                id="PH-SYSTEMD-001",
                category="systemd",
                severity=Severity.HIGH,
                title="Named pipe utility (mkfifo) in systemd unit",
                description=f"{directive_key} invokes 'mkfifo', often used to create FIFO pipes for bidirectional shell pipelines.",
                evidence=raw_value,
                location=location,
                recommendation="Audit the command pipeline and remove unauthorized unit directives."
            ))

        # 2. Remote download and piped execution
        if self.RE_DOWNLOAD_PIPE.search(cleaned):
            collection.add(Finding(
                id="PH-SYSTEMD-002",
                category="systemd",
                severity=Severity.HIGH,
                title="Remote download piped directly into shell in systemd unit",
                description=f"{directive_key} downloads remote code and pipes it directly into a shell or interpreter.",
                evidence=raw_value,
                location=location,
                recommendation="Verify the remote endpoint immediately and eliminate unverified remote downloads from services."
            ))
        elif self.RE_DOWNLOAD_TOOL.search(cleaned):
            collection.add(Finding(
                id="PH-SYSTEMD-002",
                category="systemd",
                severity=Severity.MEDIUM,
                title="Remote download utility in systemd unit",
                description=f"{directive_key} invokes a network download tool (curl/wget). Fetching remote resources directly from service definitions presents supply-chain and persistence risks.",
                evidence=raw_value,
                location=location,
                recommendation="Review the destination endpoint and ensure automated downloads in services are expected."
            ))

        # 3. Temporary / World-writable directory execution
        if self.RE_TEMP_DIRS.search(cleaned):
            collection.add(Finding(
                id="PH-SYSTEMD-003",
                category="systemd",
                severity=Severity.HIGH,
                title="Executable or script in temporary directory in systemd unit",
                description=f"{directive_key} references or executes binaries from world-writable directories (/tmp, /var/tmp, /dev/shm). Attackers frequently stage persistence payloads in these locations.",
                evidence=raw_value,
                location=location,
                recommendation="Ensure service binaries are installed in standard protected directories (e.g. /usr/bin, /usr/local/bin) owned by root."
            ))

        # 4. Hidden directory execution
        if self.RE_HIDDEN_DIR.search(exe_path):
            collection.add(Finding(
                id="PH-SYSTEMD-004",
                category="systemd",
                severity=Severity.MEDIUM,
                title="Executable located in hidden directory in systemd unit",
                description=f"{directive_key} executes a binary or script located inside a hidden directory. Legitimate system services rarely reside in hidden paths.",
                evidence=raw_value,
                location=location,
                recommendation="Investigate the binary location and relocate legitimate services to standard system paths."
            ))

        # 5. Inline interpreter execution
        if self.RE_INLINE_INTERP.search(cleaned):
            collection.add(Finding(
                id="PH-SYSTEMD-005",
                category="systemd",
                severity=Severity.MEDIUM,
                title="Inline interpreter command execution in systemd unit",
                description=f"{directive_key} uses inline script execution (-c or -e) to run code directly inside the unit file.",
                evidence=raw_value,
                location=location,
                recommendation="Inspect the inline code and migrate complex logic to an audited script file."
            ))

        # 6. User home execution in system-level service
        if not is_user_unit and self.RE_HOME_EXEC.search(exe_path):
            collection.add(Finding(
                id="PH-SYSTEMD-007",
                category="systemd",
                severity=Severity.LOW,
                title="System service executing binary from user home directory",
                description=f"{directive_key} in a system-level service executes a binary or script located in /home/. Running user-writable scripts in system services can lead to privilege escalation.",
                evidence=raw_value,
                location=location,
                recommendation="Ensure system service scripts reside in root-owned system directories or enforce strict user dropping."
            ))
