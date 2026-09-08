import os
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Union, Dict, List, Set, Any
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.detectors.base import BaseDetector, safe_read_text

@dataclass
class PasswdEntry:
    username: str
    password_placeholder: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str

@dataclass
class ShadowEntry:
    username: str
    has_empty_password: bool
    is_locked: bool
    hash_type: str
    last_change_days: Optional[int]

class AccountDetector(BaseDetector):
    """Detector for Linux user and service account persistence.

    Audits local user accounts (/etc/passwd, /etc/shadow, /etc/group) for:
    - Unexpected accounts with UID 0 (root-equivalent backdoor accounts)
    - System or daemon service accounts configured with interactive login shells
    - Accounts configured with suspicious or temporary home directories
    - Accounts with empty passwords permitting passwordless login
    - User accounts configured with unusual or non-standard shell binaries
    - Non-standard accounts granted administrative group privileges (sudo/wheel)
    - Recently created or modified local user accounts

    Strictly read-only:
    - Never modifies /etc/passwd, /etc/shadow, or /etc/group.
    - Never changes passwords or locks accounts.
    - Strictly protects privacy: never exposes or dumps raw password hashes.
    """

    name: str = "Account Persistence Detector"
    detector_id: str = "account"

    # Known standard Linux system and service accounts
    KNOWN_SYSTEM_ACCOUNTS = {
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
        "www-data",
        "backup",
        "list",
        "irc",
        "gnats",
        "nobody",
        "_apt",
        "systemd-network",
        "systemd-resolve",
        "systemd-timesync",
        "systemd-coredump",
        "messagebus",
        "sshd",
        "syslog",
        "uuidd",
        "tcpdump",
        "avahi",
        "colord",
        "dnsmasq",
        "geoclue",
        "pulse",
        "rtkit",
        "usbmux",
    }

    # Standard non-login shells
    NON_LOGIN_SHELLS = {
        "/usr/sbin/nologin",
        "/bin/false",
        "/sbin/nologin",
        "/usr/bin/false",
        "/bin/sync",
        "/usr/bin/nologin",
    }

    # Common valid system interactive shells
    VALID_INTERACTIVE_SHELLS = {
        "/bin/bash",
        "/bin/sh",
        "/bin/dash",
        "/bin/zsh",
        "/bin/ksh",
        "/bin/csh",
        "/bin/tcsh",
        "/bin/fish",
        "/usr/bin/bash",
        "/usr/bin/sh",
        "/usr/bin/dash",
        "/usr/bin/zsh",
        "/usr/bin/fish",
    }

    # Staging/temporary directories
    TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

    # Administrative group names
    ADMIN_GROUPS = {"root", "wheel", "sudo", "adm"}

    def __init__(
        self,
        root_prefix: Optional[Union[str, Path]] = None,
        passwd_path: Optional[Union[str, Path]] = None,
        shadow_path: Optional[Union[str, Path]] = None,
        group_path: Optional[Union[str, Path]] = None,
    ):
        super().__init__(name=self.name, detector_id=self.detector_id)
        self.root_prefix = Path(root_prefix) if root_prefix else None

        if passwd_path is not None:
            self.passwd_path = Path(passwd_path)
        elif self.root_prefix is not None:
            self.passwd_path = self.root_prefix / "etc" / "passwd"
        else:
            self.passwd_path = Path("/etc/passwd")

        if shadow_path is not None:
            self.shadow_path = Path(shadow_path)
        elif self.root_prefix is not None:
            self.shadow_path = self.root_prefix / "etc" / "shadow"
        else:
            self.shadow_path = Path("/etc/shadow")

        if group_path is not None:
            self.group_path = Path(group_path)
        elif self.root_prefix is not None:
            self.group_path = self.root_prefix / "etc" / "group"
        else:
            self.group_path = Path("/etc/group")

    def scan(self) -> FindingCollection:
        """Perform read-only account persistence audit."""
        collection = FindingCollection()

        # 1. Parse /etc/passwd
        passwd_entries = self._parse_passwd(collection)
        if not self.passwd_path.exists():
            return collection

        # 2. Parse /etc/shadow (if readable; safe failure on PermissionError)
        shadow_entries = self._parse_shadow(collection)

        # 3. Parse /etc/group (if readable)
        group_members = self._parse_group(collection)

        # 4. Audit each account against persistence indicators
        for entry in passwd_entries:
            self._audit_account(entry, shadow_entries.get(entry.username), group_members, collection)

        return collection

    def _parse_passwd(self, collection: FindingCollection) -> List[PasswdEntry]:
        """Safely parse /etc/passwd."""
        entries: List[PasswdEntry] = []
        if not self.passwd_path.exists():
            collection.add(Finding(
                id="PH-ACCT-090",
                category="account",
                severity=Severity.INFO,
                title="Account passwd database not found",
                description=f"Passwd database file not found at {self.passwd_path}.",
                location=str(self.passwd_path),
                recommendation="Verify system account configuration."
            ))
            return entries

        try:
            content = safe_read_text(self.passwd_path)
        except PermissionError as e:
            collection.add(Finding(
                id="PH-ACCT-090",
                category="account",
                severity=Severity.INFO,
                title="Permission denied reading passwd database",
                description=f"Could not read passwd file at {self.passwd_path}.",
                evidence=str(e),
                location=str(self.passwd_path),
                recommendation="Run PersistHunt with permissions to read /etc/passwd."
            ))
            return entries
        except OSError:
            return entries

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) >= 7:
                username = parts[0]
                placeholder = parts[1]
                uid_str = parts[2]
                gid_str = parts[3]
                gecos = parts[4]
                home = parts[5]
                shell = parts[6]

                try:
                    uid = int(uid_str)
                    gid = int(gid_str)
                except ValueError:
                    continue

                entries.append(PasswdEntry(
                    username=username,
                    password_placeholder=placeholder,
                    uid=uid,
                    gid=gid,
                    gecos=gecos,
                    home=home,
                    shell=shell,
                ))

        return entries

    def _parse_shadow(self, collection: FindingCollection) -> Dict[str, ShadowEntry]:
        """Safely parse /etc/shadow (requires root permissions)."""
        shadow_map: Dict[str, ShadowEntry] = {}
        if not self.shadow_path.exists():
            return shadow_map

        try:
            content = safe_read_text(self.shadow_path)
        except PermissionError as e:
            collection.add(Finding(
                id="PH-ACCT-090",
                category="account",
                severity=Severity.INFO,
                title="Permission denied reading shadow database",
                description=f"Could not read shadow file at {self.shadow_path} (requires elevated privileges).",
                evidence="PermissionError: [Errno 13] Permission denied",
                location=str(self.shadow_path),
                recommendation="Run PersistHunt as root to inspect password aging and hash status."
            ))
            return shadow_map
        except OSError:
            return shadow_map

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) >= 2:
                username = parts[0]
                pwd_field = parts[1]
                has_empty = (pwd_field == "")
                is_locked = pwd_field.startswith("!") or pwd_field.startswith("*")

                hash_type = "None"
                if pwd_field.startswith("$1$"):
                    hash_type = "MD5 ($1$)"
                elif pwd_field.startswith("$5$"):
                    hash_type = "SHA-256 ($5$)"
                elif pwd_field.startswith("$6$"):
                    hash_type = "SHA-512 ($6$)"
                elif pwd_field.startswith("$y$"):
                    hash_type = "yescrypt ($y$)"
                elif pwd_field.startswith("$2a$") or pwd_field.startswith("$2b$"):
                    hash_type = "bcrypt ($2$)"
                elif is_locked:
                    hash_type = "Locked"
                elif has_empty:
                    hash_type = "EMPTY"

                last_change: Optional[int] = None
                if len(parts) >= 3 and parts[2].isdigit():
                    last_change = int(parts[2])

                shadow_map[username] = ShadowEntry(
                    username=username,
                    has_empty_password=has_empty,
                    is_locked=is_locked,
                    hash_type=hash_type,
                    last_change_days=last_change,
                )

        return shadow_map

    def _parse_group(self, collection: FindingCollection) -> Dict[str, Set[str]]:
        """Parse /etc/group to map group names to members."""
        group_map: Dict[str, Set[str]] = {}
        if not self.group_path.exists():
            return group_map

        try:
            content = safe_read_text(self.group_path)
        except (OSError, PermissionError):
            return group_map

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) >= 4:
                gname = parts[0]
                members = {m.strip() for m in parts[3].split(",") if m.strip()}
                group_map[gname] = members

        return group_map

    def _audit_account(
        self,
        entry: PasswdEntry,
        shadow: Optional[ShadowEntry],
        group_members: Dict[str, Set[str]],
        collection: FindingCollection,
    ) -> None:
        """Audit an individual account against persistence indicators."""
        loc = f"{self.passwd_path}:{entry.username}"

        # 1. CRITICAL: Non-root account with UID 0
        if entry.uid == 0 and entry.username != "root":
            collection.add(Finding(
                id="PH-ACCT-001",
                category="account",
                severity=Severity.CRITICAL,
                title="Non-root user account with UID 0 (root privileges)",
                description=(
                    f"Account '{entry.username}' possesses UID 0, granting full superuser permissions. "
                    "Creating secondary UID 0 accounts is a classic persistence and backdoor technique."
                ),
                evidence=f"Username: {entry.username}, UID: 0, Home: {entry.home}, Shell: {entry.shell}",
                location=loc,
                recommendation="Investigate the authorization of this account immediately. Remove unauthorized UID 0 accounts."
            ))

        # 2. CRITICAL: Empty password hash permitting passwordless login
        if shadow and shadow.has_empty_password:
            collection.add(Finding(
                id="PH-ACCT-004",
                category="account",
                severity=Severity.CRITICAL,
                title="Account configured with empty password",
                description=(
                    f"Account '{entry.username}' has an empty password field in shadow database, "
                    "permitting unauthenticated local or remote login without credentials."
                ),
                evidence=f"Username: {entry.username}, Password Status: EMPTY",
                location=f"{self.shadow_path}:{entry.username}",
                recommendation=f"Lock or set a strong password immediately: passwd -l {entry.username}."
            ))

        # 3. HIGH: System/service account with interactive login shell
        is_system_acc = entry.username in self.KNOWN_SYSTEM_ACCOUNTS or (0 < entry.uid < 1000)
        is_interactive_shell = entry.shell in self.VALID_INTERACTIVE_SHELLS or \
            Path(entry.shell).name in ("bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh")

        if is_system_acc and entry.username != "root":
            if is_interactive_shell and entry.shell not in self.NON_LOGIN_SHELLS:
                collection.add(Finding(
                    id="PH-ACCT-002",
                    category="account",
                    severity=Severity.HIGH,
                    title="System or service account configured with interactive login shell",
                    description=(
                        f"Service account '{entry.username}' (UID {entry.uid}) is configured with an interactive "
                        f"login shell ('{entry.shell}') instead of a non-login shell (/usr/sbin/nologin or /bin/false). "
                        "Attackers often assign interactive shells to service accounts (e.g. www-data) for persistent access."
                    ),
                    evidence=f"Username: {entry.username}, UID: {entry.uid}, Shell: {entry.shell}",
                    location=loc,
                    recommendation=f"Set login shell to nologin: usermod -s /usr/sbin/nologin {entry.username}."
                ))

        # 4. HIGH: Account with suspicious home directory
        is_temp_home = any(entry.home == td or entry.home.startswith(td + "/") for td in self.TEMP_DIRS)
        home_parts = Path(entry.home).parts
        has_hidden_home = any(p.startswith(".") and p not in (".", "..") for p in home_parts)

        if is_temp_home or has_hidden_home:
            collection.add(Finding(
                id="PH-ACCT-003",
                category="account",
                severity=Severity.HIGH,
                title="Account configured with suspicious home directory",
                description=(
                    f"Account '{entry.username}' has home directory configured in a temporary or hidden path "
                    f"('{entry.home}'). This configuration is anomalous and often used by backdoors."
                ),
                evidence=f"Username: {entry.username}, Home: {entry.home}",
                location=loc,
                recommendation="Audit the user profile and relocate home directory to standard location (/home or /var)."
            ))

        # 5. HIGH: Shell path pointing to non-standard or unusual binary
        if entry.shell and entry.shell not in self.NON_LOGIN_SHELLS:
            is_temp_shell = any(entry.shell == td or entry.shell.startswith(td + "/") for td in self.TEMP_DIRS)
            is_valid_shell = entry.shell in self.VALID_INTERACTIVE_SHELLS or entry.shell.startswith(("/bin/", "/usr/bin/"))
            if is_temp_shell or not is_valid_shell:
                collection.add(Finding(
                    id="PH-ACCT-005",
                    category="account",
                    severity=Severity.HIGH,
                    title="User account configured with non-standard or unusual login shell",
                    description=(
                        f"Account '{entry.username}' is configured with a non-standard shell binary ('{entry.shell}'). "
                        "Non-standard shell binaries may execute malicious wrapper scripts upon login."
                    ),
                    evidence=f"Username: {entry.username}, Shell: {entry.shell}",
                    location=loc,
                    recommendation="Verify whether the custom shell binary is authorized and inspect its contents."
                ))

        # 6. MEDIUM: Non-standard account granted administrative group privileges
        if entry.username not in ("root",) and entry.uid >= 1000:
            for admin_group in self.ADMIN_GROUPS:
                if admin_group in group_members and entry.username in group_members[admin_group]:
                    collection.add(Finding(
                        id="PH-ACCT-006",
                        category="account",
                        severity=Severity.MEDIUM,
                        title=f"User account is member of administrative group '{admin_group}'",
                        description=(
                            f"Account '{entry.username}' (UID {entry.uid}) has administrative privileges through "
                            f"membership in group '{admin_group}'. Verify administrative authorization."
                        ),
                        evidence=f"Username: {entry.username}, Group: {admin_group}",
                        location=f"{self.group_path}:{admin_group}",
                        recommendation=f"Review whether '{entry.username}' requires administrative privileges in group '{admin_group}'."
                    ))

        # 7. LOW: Recently modified or created account
        if shadow and shadow.last_change_days is not None:
            current_days = int(time.time() / 86400)
            days_ago = current_days - shadow.last_change_days
            # If account password was modified or created within last 7 days
            if 0 <= days_ago <= 7 and entry.username != "root":
                collection.add(Finding(
                    id="PH-ACCT-007",
                    category="account",
                    severity=Severity.LOW,
                    title="Recently created or modified local account",
                    description=(
                        f"Account '{entry.username}' had its password or credentials modified {days_ago} day(s) ago. "
                        "Recently created accounts should be reviewed during security investigations."
                    ),
                    evidence=f"Username: {entry.username}, Days since last change: {days_ago}",
                    location=f"{self.shadow_path}:{entry.username}",
                    recommendation="Verify that the account creation or password update was an authorized administrative action."
                ))
