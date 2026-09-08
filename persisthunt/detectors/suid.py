import os
import stat
import pwd
import grp
from pathlib import Path
from typing import Optional, Union, Iterable, List, Set, Dict
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector

class SuidDetector(BaseDetector):
    """Detector for Linux SUID and SGID persistence mechanisms.

    Enumerates binaries with SUID (chmod u+s) and SGID (chmod g+s) permissions
    across system binary paths, staging directories (/tmp, /var/tmp, /dev/shm),
    user home directories, and system paths.

    Adheres to strict read-only auditing safety: never executes discovered
    binaries, never attempts privilege escalation, and never modifies file
    permissions or ownership.
    """

    name: str = "SUID/SGID Persistence Detector"
    detector_id: str = "suid"

    # Default search paths on Linux
    DEFAULT_SEARCH_PATHS = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/lib",
        "/usr/libexec",
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/home",
        "/root",
        "/opt",
    ]

    # Standard system binary directories
    STANDARD_SYSTEM_PATHS = {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/lib",
        "/usr/libexec",
    }

    # Shells and script interpreters that should never possess SUID/SGID bits
    KNOWN_SHELLS_AND_INTERPRETERS = {
        "bash",
        "sh",
        "dash",
        "zsh",
        "csh",
        "tcsh",
        "ksh",
        "fish",
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "lua",
        "php",
        "node",
        "busybox",
    }

    def __init__(
        self,
        root_prefix: Optional[Union[str, Path]] = None,
        search_paths: Optional[Iterable[Union[str, Path]]] = None,
        custom_files: Optional[Iterable[Union[str, Path]]] = None,
    ):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.root_prefix = Path(root_prefix) if root_prefix else None

        if search_paths is not None:
            self.search_paths = [self._resolve_path(p) for p in search_paths]
        else:
            self.search_paths = [self._resolve_path(p) for p in self.DEFAULT_SEARCH_PATHS]

        self.custom_files = (
            [self._resolve_path(f) for f in custom_files]
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
        """Enumerate SUID/SGID files and return a FindingCollection."""
        collection = FindingCollection()
        scanned_files: Set[str] = set()

        # 1. Enumerate configured search paths
        for search_path in self.search_paths:
            if not search_path.exists():
                continue

            if search_path.is_file():
                self._audit_file(search_path, scanned_files, collection)
            elif search_path.is_dir():
                self._traverse_directory(search_path, scanned_files, collection)

        # 2. Enumerate any explicitly configured files
        for c_file in self.custom_files:
            if c_file.exists():
                self._audit_file(c_file, scanned_files, collection)

        return collection

    def _traverse_directory(
        self, dir_path: Path, scanned_files: Set[str], collection: FindingCollection
    ) -> None:
        """Traverse a directory recursively to discover SUID/SGID files."""
        try:
            entries = list(os.scandir(dir_path))
        except PermissionError as e:
            collection.add(Finding(
                id="PH-SUID-090",
                category="suid",
                severity=Severity.INFO,
                title="Unreadable directory during SUID scan (permission denied)",
                description=f"Permission was denied when accessing directory {dir_path}.",
                evidence=str(e),
                location=str(dir_path),
                recommendation="Run PersistHunt with elevated permissions if complete filesystem enumeration is required."
            ))
            return
        except OSError:
            return

        for entry in entries:
            # Skip symlinks (do not follow symlinks, as SUID bits on symlinks are ignored)
            try:
                if entry.is_symlink():
                    continue
            except OSError:
                continue

            try:
                if entry.is_dir():
                    # Avoid traversing pseudo/virtual filesystems
                    if entry.name in ("proc", "sys", "dev", "run") and str(dir_path) in ("/", str(self.root_prefix)):
                        continue
                    # Skip common massive developer / cache directory trees to ensure fast scanning
                    if entry.name in (".git", ".cache", ".cargo", "node_modules", "__pycache__", ".npm"):
                        continue
                    self._traverse_directory(Path(entry.path), scanned_files, collection)
                elif entry.is_file():
                    # Fast check: only stat and process files with SUID or SGID bits
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except (OSError, PermissionError):
                        continue
                    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        self._audit_file(Path(entry.path), scanned_files, collection, st=st)
            except OSError:
                continue

    def _audit_file(
        self,
        file_path: Path,
        scanned_files: Set[str],
        collection: FindingCollection,
        st: Optional[os.stat_result] = None,
    ) -> None:
        """Inspect a file for SUID and SGID permissions and evaluate risk."""
        if st is None:
            try:
                st = file_path.stat(follow_symlinks=False)
            except (OSError, PermissionError):
                return

        mode = st.st_mode
        has_suid = bool(mode & stat.S_ISUID)
        has_sgid = bool(mode & stat.S_ISGID)

        # Only evaluate files with SUID or SGID bits set
        if not (has_suid or has_sgid):
            return

        try:
            canonical = str(file_path.resolve()) if file_path.exists() else str(file_path)
        except OSError:
            canonical = str(file_path)

        if canonical in scanned_files:
            return
        scanned_files.add(canonical)

        octal_mode = oct(mode & 0o7777)
        uid = st.st_uid
        gid = st.st_gid

        try:
            owner_name = pwd.getpwuid(uid).pw_name
        except (KeyError, AttributeError):
            owner_name = str(uid)

        try:
            group_name = grp.getgrgid(gid).gr_name
        except (KeyError, AttributeError):
            group_name = str(gid)

        is_world_writable = bool(mode & 0o002)
        is_group_writable = bool(mode & 0o020)
        fname_lower = file_path.name.lower()

        # Compute logical path relative to root_prefix (if set)
        if self.root_prefix is not None:
            try:
                rel = file_path.relative_to(self.root_prefix)
                logical_path = "/" + str(rel).replace("\\", "/")
            except ValueError:
                logical_path = str(file_path)
        else:
            logical_path = str(file_path)

        evidence = (
            f"Permissions: {octal_mode}, Owner: {owner_name}:{group_name}, "
            f"SUID: {has_suid}, SGID: {has_sgid}"
        )
        loc = str(file_path)

        # 1. CRITICAL: Insecure writable permissions on SUID/SGID binary
        if is_world_writable or is_group_writable:
            collection.add(Finding(
                id="PH-SUID-002",
                category="suid",
                severity=Severity.CRITICAL,
                title="Insecure writable permissions on SUID/SGID binary",
                description=(
                    f"Binary at {file_path} has SUID/SGID bits set and is "
                    f"{'world-writable' if is_world_writable else 'group-writable'} ({octal_mode}). "
                    "Any local user can overwrite the binary to execute arbitrary code with elevated privileges."
                ),
                evidence=evidence,
                location=loc,
                recommendation=f"Remove write permissions immediately: chmod go-w {file_path}."
            ))

        # 2. HIGH: Shell or script interpreter possessing SUID/SGID bits
        if fname_lower in self.KNOWN_SHELLS_AND_INTERPRETERS:
            collection.add(Finding(
                id="PH-SUID-003",
                category="suid",
                severity=Severity.HIGH,
                title="Shell or script interpreter possesses SUID/SGID permissions",
                description=(
                    f"Interpreter '{file_path.name}' at {file_path} has SUID/SGID bits set ({octal_mode}). "
                    "Interactive interpreters with SUID permissions allow immediate unconstrained root shell access."
                ),
                evidence=evidence,
                location=loc,
                recommendation=f"Remove the SUID/SGID bit immediately: chmod u-s,g-s {file_path}."
            ))
            return

        # 3. HIGH: SUID/SGID binary in temporary or staging directory
        if any(
            logical_path.startswith(temp_dir + "/") or logical_path == temp_dir
            for temp_dir in ("/tmp", "/var/tmp", "/dev/shm")
        ):
            collection.add(Finding(
                id="PH-SUID-001",
                category="suid",
                severity=Severity.HIGH,
                title="SUID/SGID binary in temporary or world-writable directory",
                description=(
                    f"Binary {file_path} possesses SUID/SGID bits and resides in a temporary directory. "
                    "This is a primary persistence and privilege-escalation technique used by attackers."
                ),
                evidence=evidence,
                location=loc,
                recommendation="Investigate the binary origin immediately, revoke permissions (chmod 000), and remove unauthorized files."
            ))
            return

        # 4. HIGH: SUID/SGID binary in user directory (/home/* or /root/*)
        if logical_path.startswith("/home/") or logical_path.startswith("/root/") or logical_path in ("/home", "/root"):
            collection.add(Finding(
                id="PH-SUID-001",
                category="suid",
                severity=Severity.HIGH,
                title="SUID/SGID binary located in user directory",
                description=(
                    f"Binary {file_path} has SUID/SGID permissions inside a user directory. "
                    "Elevated binaries in user paths present severe persistence and privilege escalation risks."
                ),
                evidence=evidence,
                location=loc,
                recommendation="Verify whether this elevated binary is authorized and remove SUID/SGID bits if unexpected."
            ))
            return

        # 5. Standard system binary path vs Non-standard directory
        is_standard_path = False
        for std_dir in self.STANDARD_SYSTEM_PATHS:
            if logical_path.startswith(std_dir + "/") or logical_path == std_dir:
                is_standard_path = True
                break

        if not is_standard_path:
            collection.add(Finding(
                id="PH-SUID-004",
                category="suid",
                severity=Severity.MEDIUM,
                title="SUID/SGID binary located in non-standard system directory",
                description=(
                    f"Binary {file_path} has SUID/SGID permissions in a non-standard directory. "
                    "Non-standard SUID binaries warrant review to confirm legitimate administrative purpose."
                ),
                evidence=evidence,
                location=loc,
                recommendation="Audit the package ownership and authorization for this binary."
            ))
        else:
            # Standard system SUID binary (e.g. /usr/bin/passwd, /usr/bin/sudo)
            collection.add(Finding(
                id="PH-SUID-005",
                category="suid",
                severity=Severity.INFO,
                title="Standard system SUID/SGID binary",
                description=(
                    f"Standard system binary {file_path.name} possesses elevated SUID/SGID bits ({octal_mode}). "
                    "This is an expected system configuration under normal operating parameters."
                ),
                evidence=evidence,
                location=loc,
                recommendation="Ensure the binary is verified against package management integrity databases (e.g. debsums, rpm -V)."
            ))
