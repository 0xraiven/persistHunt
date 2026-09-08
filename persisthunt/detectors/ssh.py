import os
import re
import base64
import hashlib
from pathlib import Path
from typing import Optional, Union, Iterable, List, Set, Tuple
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector, safe_read_lines

class SSHDetector(BaseDetector):
    """Detector for Linux SSH persistence mechanisms.

    Audits root and user authorized_keys files, SSH daemon configuration
    (sshd_config, sshd_config.d), key options (forced commands), insecure
    filesystem permissions, and anomalous service account keys.

    Adheres to strict read-only auditing and credential safety: never modifies
    keys or configuration, never executes commands, never prints private keys,
    and fingerprints public keys instead of dumping raw key material.
    """

    name: str = "SSH Persistence Detector"
    detector_id: str = "ssh"

    # Known standard SSH public key types
    KNOWN_KEY_TYPES = {
        "ssh-rsa",
        "ssh-dss",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-rsa-cert-v01@openssh.com",
        "ssh-dss-cert-v01@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    }

    # Indicator Patterns for Forced Commands
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

    # Common system/service account names that should not possess authorized_keys
    SERVICE_ACCOUNTS = {
        "www-data",
        "nobody",
        "daemon",
        "bin",
        "sys",
        "sync",
        "games",
        "man",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "apache",
        "nginx",
        "mysql",
        "postgres",
        "redis",
        "mongodb",
    }

    def __init__(
        self,
        root_prefix: Optional[Union[str, Path]] = None,
        root_ssh_dir: Optional[Union[str, Path]] = None,
        home_dir: Optional[Union[str, Path]] = None,
        sshd_config_path: Optional[Union[str, Path]] = None,
        sshd_config_d: Optional[Union[str, Path]] = None,
        custom_key_files: Optional[Iterable[Union[str, Path]]] = None,
        service_account_dirs: Optional[Iterable[Union[str, Path]]] = None,
    ):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.root_prefix = Path(root_prefix) if root_prefix else None

        self.root_ssh_dir = self._resolve_path(root_ssh_dir or "/root/.ssh")
        self.home_dir = self._resolve_path(home_dir or "/home")
        self.sshd_config_path = self._resolve_path(sshd_config_path or "/etc/ssh/sshd_config")
        self.sshd_config_d = self._resolve_path(sshd_config_d or "/etc/ssh/sshd_config.d")

        self.custom_key_files = (
            [self._resolve_path(p) for p in custom_key_files]
            if custom_key_files is not None
            else []
        )

        if service_account_dirs is not None:
            self.service_account_dirs = [self._resolve_path(d) for d in service_account_dirs]
        else:
            default_svc = ["/var/www", "/var/lib/nobody", "/srv"]
            self.service_account_dirs = [self._resolve_path(d) for d in default_svc]

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
        """Scan SSH persistence locations and return a FindingCollection."""
        collection = FindingCollection()
        scanned_files: Set[str] = set()

        # 1. Audit root authorized_keys
        self._audit_ssh_directory(
            ssh_dir=self.root_ssh_dir,
            is_root=True,
            is_service_account=False,
            scanned_files=scanned_files,
            collection=collection,
        )

        # 2. Audit /home/*/.ssh/authorized_keys
        try:
            home_exists = self.home_dir.exists()
        except (OSError, PermissionError):
            home_exists = False

        if home_exists:
            try:
                user_entries = list(os.scandir(self.home_dir))
            except PermissionError as e:
                collection.add(Finding(
                    id="PH-SSH-090",
                    category="ssh",
                    severity=Severity.INFO,
                    title="Unreadable home directory (permission denied)",
                    description=f"Permission was denied when listing {self.home_dir}.",
                    evidence=str(e),
                    location=str(self.home_dir),
                    recommendation="Run PersistHunt with elevated permissions if complete user auditing is required."
                ))
                user_entries = []
            except OSError:
                user_entries = []

            for u_entry in user_entries:
                if u_entry.is_dir():
                    user_ssh_dir = Path(u_entry.path) / ".ssh"
                    is_svc = u_entry.name in self.SERVICE_ACCOUNTS
                    self._audit_ssh_directory(
                        ssh_dir=user_ssh_dir,
                        is_root=False,
                        is_service_account=is_svc,
                        scanned_files=scanned_files,
                        collection=collection,
                    )

        # 3. Audit common service account homes (e.g. /var/www/.ssh)
        for svc_dir in self.service_account_dirs:
            svc_ssh = svc_dir / ".ssh"
            self._audit_ssh_directory(
                ssh_dir=svc_ssh,
                is_root=False,
                is_service_account=True,
                scanned_files=scanned_files,
                collection=collection,
            )

        # 4. Audit any custom files explicitly supplied
        for c_file in self.custom_key_files:
            try:
                c_exists = c_file.exists()
            except (OSError, PermissionError):
                c_exists = False
            if not c_exists:
                continue
            try:
                canonical = str(c_file.resolve())
            except (OSError, PermissionError):
                canonical = str(c_file)
            if canonical not in scanned_files:
                scanned_files.add(canonical)
                self._check_permissions(c_file, is_dir=False, collection=collection)
                self._audit_key_file(
                    file_path=c_file,
                    is_root=False,
                    is_service_account=False,
                    collection=collection,
                )

        # 5. Audit SSH daemon configuration
        self._audit_sshd_config(collection)

        return collection

    def _audit_ssh_directory(
        self,
        ssh_dir: Path,
        is_root: bool,
        is_service_account: bool,
        scanned_files: Set[str],
        collection: FindingCollection,
    ) -> None:
        """Inspect a .ssh directory and its authorized_keys files."""
        try:
            if not ssh_dir.exists():
                return
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SSH-090",
                category="ssh",
                severity=Severity.INFO,
                title="Unreadable .ssh directory (permission denied)",
                description=f"Permission was denied when accessing {ssh_dir}.",
                evidence=str(e),
                location=str(ssh_dir),
                recommendation="Run PersistHunt with elevated permissions if complete auditing is required."
            ))
            return
        except OSError:
            return

        # Check directory permissions
        self._check_permissions(ssh_dir, is_dir=True, collection=collection)

        # Check for broken symlinks and hidden/unusual files in .ssh
        try:
            entries = list(os.scandir(ssh_dir))
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SSH-090",
                category="ssh",
                severity=Severity.INFO,
                title="Unreadable .ssh directory (permission denied)",
                description=f"Permission was denied when listing {ssh_dir}.",
                evidence=str(e),
                location=str(ssh_dir),
                recommendation="Run PersistHunt with elevated permissions if complete auditing is required."
            ))
            return
        except OSError:
            return

        for entry in entries:
            entry_path = Path(entry.path)
            is_broken = False
            if entry.is_symlink():
                try:
                    is_broken = not entry_path.exists()
                except (OSError, PermissionError):
                    is_broken = False
            if is_broken:
                collection.add(Finding(
                    id="PH-SSH-091",
                    category="ssh",
                    severity=Severity.LOW,
                    title="Broken symlink in .ssh directory",
                    description=f"Symlink at {entry_path} points to a missing target.",
                    evidence=f"Symlink target: {os.readlink(entry.path)}",
                    location=str(entry_path),
                    recommendation="Remove or repair dangling symlinks in SSH directory."
                ))
                continue

            if entry.name in ("authorized_keys", "authorized_keys2"):
                try:
                    canonical = str(entry_path.resolve())
                except (OSError, PermissionError):
                    canonical = str(entry_path)
                if canonical not in scanned_files:
                    scanned_files.add(canonical)
                    self._check_permissions(entry_path, is_dir=False, collection=collection)
                    self._audit_key_file(
                        file_path=entry_path,
                        is_root=is_root,
                        is_service_account=is_service_account,
                        collection=collection,
                    )

    def _check_permissions(self, path: Path, is_dir: bool, collection: FindingCollection) -> None:
        """Verify that SSH directories and files are not world or group writable."""
        try:
            st = path.stat()
            mode = st.st_mode
            octal = oct(mode & 0o777)

            if (mode & 0o002) != 0:
                collection.add(Finding(
                    id="PH-SSH-004",
                    category="ssh",
                    severity=Severity.HIGH,
                    title=f"Insecure world-writable {'directory' if is_dir else 'file'} in SSH path",
                    description=f"{'Directory' if is_dir else 'File'} at {path} is world-writable ({octal}). Any local user can tamper with SSH persistence.",
                    evidence=f"Permissions: {octal}",
                    location=str(path),
                    recommendation=f"Restrict permissions immediately: chmod {'700' if is_dir else '600'} {path}."
                ))
            elif (mode & 0o020) != 0:
                collection.add(Finding(
                    id="PH-SSH-004",
                    category="ssh",
                    severity=Severity.MEDIUM,
                    title=f"Insecure group-writable {'directory' if is_dir else 'file'} in SSH path",
                    description=f"{'Directory' if is_dir else 'File'} at {path} is group-writable ({octal}). Members of this group can alter SSH authorization.",
                    evidence=f"Permissions: {octal}",
                    location=str(path),
                    recommendation=f"Restrict group write permissions: chmod {'700' if is_dir else '600'} {path}."
                ))
        except (OSError, PermissionError):
            pass

    def _audit_key_file(
        self,
        file_path: Path,
        is_root: bool,
        is_service_account: bool,
        collection: FindingCollection,
    ) -> None:
        try:
            if not file_path.exists():
                return
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SSH-090",
                category="ssh",
                severity=Severity.INFO,
                title="Unreadable authorized_keys file (permission denied)",
                description=f"Permission was denied when accessing {file_path}.",
                evidence=str(e),
                location=str(file_path),
                recommendation="Run PersistHunt with elevated permissions if complete key auditing is required."
            ))
            return
        except OSError:
            return

        try:
            lines = safe_read_lines(file_path)
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SSH-090",
                category="ssh",
                severity=Severity.INFO,
                title="Unreadable authorized_keys file (permission denied)",
                description=f"Permission was denied when reading {file_path}.",
                evidence=str(e),
                location=str(file_path),
                recommendation="Run PersistHunt with elevated permissions if complete key auditing is required."
            ))
            return
        except OSError as e:
            collection.add(Finding(
                id="PH-SSH-090",
                category="ssh",
                severity=Severity.INFO,
                title="Error accessing authorized_keys file",
                description=f"OS error reading {file_path}: {e}",
                evidence=str(e),
                location=str(file_path),
                recommendation="Verify filesystem integrity for this file."
            ))
            return

        valid_keys_count = 0
        in_private_key = False

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            loc = f"{file_path}:{line_no}"

            # Check if private key material was accidentally or maliciously placed
            if "-----BEGIN" in line and "PRIVATE KEY" in line:
                in_private_key = True
                collection.add(Finding(
                    id="PH-SSH-005",
                    category="ssh",
                    severity=Severity.HIGH,
                    title="Private key material detected in authorized_keys file",
                    description=f"Private key material was detected inside {file_path}. Private keys must never be stored in authorized_keys files.",
                    evidence="[REDACTED PRIVATE KEY MATERIAL]",
                    location=loc,
                    recommendation="Remove the private key immediately, regenerate affected credentials, and store private keys only in secure private storage."
                ))
                continue

            if in_private_key:
                if "-----END" in line and "PRIVATE KEY" in line:
                    in_private_key = False
                continue

            parsed = self._parse_authorized_key_line(line)
            if parsed is None:
                collection.add(Finding(
                    id="PH-SSH-092",
                    category="ssh",
                    severity=Severity.LOW,
                    title="Malformed authorized_keys entry",
                    description=f"Line could not be parsed as a valid OpenSSH authorized_keys entry.",
                    evidence=line[:80] + ("..." if len(line) > 80 else ""),
                    location=loc,
                    recommendation="Verify authorized_keys line format."
                ))
                continue

            options, key_type, base64_blob, comment = parsed
            valid_keys_count += 1
            fingerprint = self._compute_fingerprint(base64_blob)

            # Build safe evidence string (never dumping raw base64 key blob)
            evidence_items = [f"Type: {key_type}", f"Fingerprint: {fingerprint}"]
            if comment:
                evidence_items.append(f"Comment: {comment}")
            if options:
                evidence_items.append(f"Options: {options}")
            safe_evidence = ", ".join(evidence_items)

            # Check for forced command in options
            if options:
                self._check_key_options(options, safe_evidence, loc, collection)

        # Service account possessing authorized keys
        if is_service_account and valid_keys_count > 0:
            collection.add(Finding(
                id="PH-SSH-003",
                category="ssh",
                severity=Severity.HIGH,
                title="SSH authorized keys found on service account",
                description=f"Service account path {file_path} contains {valid_keys_count} authorized SSH key(s). System and daemon service accounts should not possess interactive SSH keys.",
                evidence=f"Keys count: {valid_keys_count}",
                location=str(file_path),
                recommendation="Audit authorized keys on this service account and remove them if interactive SSH access is not required."
            ))

        # Root authorized keys observation
        if is_root and valid_keys_count > 0:
            collection.add(Finding(
                id="PH-SSH-001",
                category="ssh",
                severity=Severity.LOW,
                title="Root SSH authorized keys configured",
                description=f"Root account possesses {valid_keys_count} authorized SSH key(s) allowing direct root login.",
                evidence=f"Active root keys count: {valid_keys_count}",
                location=str(file_path),
                recommendation="Verify that direct root SSH access via key is authorized by administrative policy."
            ))

    def _parse_authorized_key_line(
        self, line: str
    ) -> Optional[Tuple[str, str, str, str]]:
        """Parse an authorized_keys line into (options, key_type, base64_blob, comment)."""
        tokens = line.split()
        if len(tokens) < 2:
            return None

        # Case 1: No options - line begins directly with key type
        if tokens[0] in self.KNOWN_KEY_TYPES:
            key_type = tokens[0]
            base64_blob = tokens[1]
            comment = " ".join(tokens[2:]) if len(tokens) > 2 else ""
            return ("", key_type, base64_blob, comment)

        # Case 2: Line has leading options before the key type
        # Find index of the key type token
        key_type_idx = -1
        for idx, token in enumerate(tokens):
            if token in self.KNOWN_KEY_TYPES:
                key_type_idx = idx
                break

        if key_type_idx > 0 and len(tokens) > key_type_idx + 1:
            options = " ".join(tokens[:key_type_idx])
            key_type = tokens[key_type_idx]
            base64_blob = tokens[key_type_idx + 1]
            comment = " ".join(tokens[key_type_idx + 2:]) if len(tokens) > key_type_idx + 2 else ""
            return (options, key_type, base64_blob, comment)

        return None

    def _compute_fingerprint(self, base64_blob: str) -> str:
        """Compute SHA256 OpenSSH-compatible fingerprint of public key."""
        try:
            raw = base64.b64decode(base64_blob)
            digest = hashlib.sha256(raw).digest()
            b64_digest = base64.b64encode(digest).decode("ascii").rstrip("=")
            return f"SHA256:{b64_digest}"
        except Exception:
            return "SHA256:invalid"

    def _check_key_options(
        self, options: str, safe_evidence: str, location: str, collection: FindingCollection
    ) -> None:
        """Analyze key options, particularly forced commands."""
        # Extract command="..." value
        cmd_match = re.search(r'command="([^"]*)"', options)
        if cmd_match:
            forced_cmd = cmd_match.group(1)

            # Check if forced command contains suspicious indicators
            is_suspicious = False
            reasons = []

            if self.RE_SOCKET_DEV.search(forced_cmd) or self.RE_NETCAT.search(forced_cmd) or self.RE_MKFIFO.search(forced_cmd):
                is_suspicious = True
                reasons.append("network socket / reverse shell utility")
            if self.RE_DOWNLOAD_PIPE.search(forced_cmd) or self.RE_DOWNLOAD_TOOL.search(forced_cmd):
                is_suspicious = True
                reasons.append("remote download tool or piped execution")
            if self.RE_TEMP_DIRS.search(forced_cmd):
                is_suspicious = True
                reasons.append("temporary directory path (/tmp, /var/tmp, /dev/shm)")
            if self.RE_INLINE_INTERP.search(forced_cmd):
                is_suspicious = True
                reasons.append("inline interpreter execution (-c or -e)")

            if is_suspicious:
                collection.add(Finding(
                    id="PH-SSH-002",
                    category="ssh",
                    severity=Severity.HIGH,
                    title="Suspicious forced command in SSH authorized key",
                    description=f"Authorized key enforces execution of command containing suspicious characteristics: {', '.join(reasons)}.",
                    evidence=safe_evidence,
                    location=location,
                    recommendation="Review the forced command immediately and revoke the key if unauthorized."
                ))
            else:
                collection.add(Finding(
                    id="PH-SSH-002",
                    category="ssh",
                    severity=Severity.MEDIUM,
                    title="Forced command configured in SSH authorized key",
                    description="Authorized key enforces execution of a command upon connection, bypassing normal shell execution.",
                    evidence=safe_evidence,
                    location=location,
                    recommendation="Verify that the forced command is intended for restricted access (e.g. git, backup)."
                ))

    def _audit_sshd_config(self, collection: FindingCollection) -> None:
        """Audit /etc/ssh/sshd_config and drop-in configurations."""
        config_files: List[Path] = []

        try:
            if self.sshd_config_path.exists():
                config_files.append(self.sshd_config_path)
        except (OSError, PermissionError):
            pass

        try:
            if self.sshd_config_d.exists():
                try:
                    for entry in os.scandir(self.sshd_config_d):
                        if entry.is_file() and entry.name.endswith(".conf"):
                            config_files.append(Path(entry.path))
                except (OSError, PermissionError):
                    pass
        except (OSError, PermissionError):
            pass

        for cfg in config_files:
            try:
                lines = safe_read_lines(cfg)
            except PermissionError as e:
                collection.add(Finding(
                    id="PH-SSH-090",
                    category="ssh",
                    severity=Severity.INFO,
                    title="Unreadable SSH daemon configuration (permission denied)",
                    description=f"Permission was denied when reading {cfg}.",
                    evidence=str(e),
                    location=str(cfg),
                    recommendation="Run PersistHunt with elevated permissions if complete configuration auditing is required."
                ))
                continue
            except OSError:
                continue

            for line_no, raw_line in enumerate(lines, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    continue

                key, val = parts[0].lower(), parts[1].strip()
                loc = f"{cfg}:{line_no}"

                # 1. PermitEmptyPasswords yes
                if key == "permitemptypasswords" and val.lower() == "yes":
                    collection.add(Finding(
                        id="PH-SSH-006",
                        category="ssh",
                        severity=Severity.HIGH,
                        title="SSH daemon permits empty passwords",
                        description="PermitEmptyPasswords is set to 'yes', allowing login to accounts with empty passwords.",
                        evidence=line,
                        location=loc,
                        recommendation="Set 'PermitEmptyPasswords no' in sshd_config and restart sshd."
                    ))

                # 2. AuthorizedKeysFile in temporary or writable directory
                if key == "authorizedkeysfile" and self.RE_TEMP_DIRS.search(val):
                    collection.add(Finding(
                        id="PH-SSH-006",
                        category="ssh",
                        severity=Severity.HIGH,
                        title="AuthorizedKeysFile points to temporary directory",
                        description=f"AuthorizedKeysFile points to world-writable temporary path '{val}', allowing any local user to plant authorized keys.",
                        evidence=line,
                        location=loc,
                        recommendation="Restore AuthorizedKeysFile to standard user directory (.ssh/authorized_keys)."
                    ))

                # 3. PermitRootLogin yes (unrestricted root login)
                if key == "permitrootlogin" and val.lower() == "yes":
                    collection.add(Finding(
                        id="PH-SSH-006",
                        category="ssh",
                        severity=Severity.MEDIUM,
                        title="Unrestricted root login enabled in SSH daemon",
                        description="PermitRootLogin is set to 'yes', permitting unrestricted direct root login.",
                        evidence=line,
                        location=loc,
                        recommendation="Consider setting 'PermitRootLogin prohibit-password' or 'no'."
                    ))

                # 4. AuthorizedKeysCommand configured
                if key == "authorizedkeyscommand" and val:
                    collection.add(Finding(
                        id="PH-SSH-006",
                        category="ssh",
                        severity=Severity.MEDIUM,
                        title="External AuthorizedKeysCommand configured in SSH daemon",
                        description=f"AuthorizedKeysCommand executes an external command '{val}' to generate authorized keys.",
                        evidence=line,
                        location=loc,
                        recommendation="Ensure the AuthorizedKeysCommand executable is audited and root-owned."
                    ))
