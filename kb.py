from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
from ingest_nmap import Host, Service

@dataclass(frozen=True)
class Technique:
    id: str
    title: str
    severity: str          
    category: str          
    family: str            
    applies: Callable[[Host, Service], bool]
    base_p: float          
    effort_hours: float    
    base_days: int         
    fix: str               

def svc(name: str, ports: set[int] | None = None):
    def _f(host: Host, s: Service) -> bool:
        if s.name != name:
            return False
        if ports is not None and s.port not in ports:
            return False
        return True
    return _f

def anysvc(names: set[str], ports: set[int] | None = None):
    def _f(host: Host, s: Service) -> bool:
        if s.name not in names:
            return False
        if ports is not None and s.port not in ports:
            return False
        return True
    return _f

def is_web(s: Service) -> bool:
    
    return s.name in {"http", "https"} or (s.product and any(x in s.product for x in ["nginx", "Apache", "LiteSpeed"]))

KB: list[Technique] = [
    
    Technique(
        id="T-WEB-EXPOSED",
        title="Externally exposed web surface",
        severity="MED",
        category="Exposure",
        family="WEB",
        applies=lambda h, s: is_web(s) and s.port in {80, 443, 8080, 8443},
        base_p=0.22, effort_hours=6.0, base_days=7,
        fix=(
            "Edge:\n"
            "- Restrict admin paths to VPN/allowlist (e.g., /admin, /wp-admin).\n"
            "- Add WAF (managed rules) + rate-limit auth endpoints.\n"
            "App:\n"
            "- Patch web stack; remove unused modules/vhosts.\n"
            "- Enforce secure headers; disable directory listing.\n"
            "Telemetry:\n"
            "- Log auth failures; alert on spikes / credential-stuffing patterns."
        )
    ),

    
    Technique(
        id="T-SSH-EXPOSED",
        title="SSH exposed (credential window)",
        severity="MED",
        category="Auth",
        family="REMOTE",
        applies=svc("ssh", {22}),
        base_p=0.16, effort_hours=8.0, base_days=10,
        fix=(
            "Config (sshd_config):\n"
            "- PasswordAuthentication no\n"
            "- PermitRootLogin no\n"
            "- AllowUsers / AllowGroups (least access)\n"
            "Network:\n"
            "- Allowlist source IPs at firewall; prefer VPN/bastion.\n"
            "Protection:\n"
            "- fail2ban; MaxAuthTries low; strong keys only.\n"
            "Monitoring:\n"
            "- Alert on repeated failures and new geo/IP logins."
        )
    ),
    Technique(
        id="T-RDP-EXPOSED",
        title="RDP exposed to internet",
        severity="HIGH",
        category="Auth",
        family="REMOTE",
        applies=svc("ms-wbt-server", {3389}),
        base_p=0.28, effort_hours=10.0, base_days=7,
        fix=(
            "Network:\n"
            "- Block 3389 from internet; require VPN or RD Gateway.\n"
            "Identity:\n"
            "- Enforce NLA + MFA; lockout policy; disable local admin RDP.\n"
            "Detection:\n"
            "- Monitor Windows auth events (4625/4624) and RDP session creation."
        )
    ),
    Technique(
        id="T-VNC-EXPOSED",
        title="VNC exposed",
        severity="HIGH",
        category="Auth",
        family="REMOTE",
        applies=anysvc({"vnc", "vnc-http"}, {5900, 5800}),
        base_p=0.30, effort_hours=6.0, base_days=5,
        fix=(
            "Network:\n"
            "- Remove VNC from internet; tunnel via VPN/SSH.\n"
            "Access:\n"
            "- Strong auth; disable no-auth modes; allowlist only.\n"
            "Ops:\n"
            "- Centralize via bastion; alert on new sessions."
        )
    ),
    Technique(
        id="T-TELNET-EXPOSED",
        title="Telnet exposed (legacy remote shell)",
        severity="HIGH",
        category="Auth",
        family="LEGACY",
        applies=svc("telnet", {23}),
        base_p=0.35, effort_hours=4.0, base_days=3,
        fix="Disable Telnet; migrate to SSH. Block 23/tcp at edge firewall."
    ),

    
    Technique(
        id="T-FTP-EXPOSED",
        title="FTP exposed (legacy file service risk)",
        severity="HIGH",
        category="Exposure",
        family="LEGACY",
        applies=svc("ftp", {21}),
        base_p=0.26, effort_hours=7.0, base_days=10,
        fix=(
            "Replace:\n"
            "- Prefer SFTP/FTPS; remove plain FTP if possible.\n"
            "If must keep:\n"
            "- Disable anonymous; chroot users; allowlist IPs.\n"
            "- Strong auth; monitor writes; rotate creds.\n"
            "Edge:\n"
            "- Block from internet unless explicitly required."
        )
    ),

    
    Technique(
        id="T-SMTP-EXPOSED",
        title="SMTP exposed (mail perimeter)",
        severity="MED",
        category="Exposure",
        family="MAIL",
        applies=anysvc({"smtp"}, {25, 465, 587}),
        base_p=0.14, effort_hours=10.0, base_days=14,
        fix=(
            "TLS/Auth:\n"
            "- Prefer 587 submission; enforce STARTTLS; disable weak AUTH.\n"
            "Abuse control:\n"
            "- Rate-limit auth; greylisting (if appropriate); monitor relay config.\n"
            "Email security:\n"
            "- SPF/DKIM/DMARC to reduce spoofing and abuse.\n"
            "Patching:\n"
            "- Keep MTA updated; apply security releases promptly."
        )
    ),
    Technique(
        id="T-IMAPPOP-EXPOSED",
        title="IMAP/POP exposed (credential surface)",
        severity="HIGH",
        category="Auth",
        family="MAIL",
        applies=anysvc({"imap", "pop3"}, {110, 143, 993, 995}),
        base_p=0.22, effort_hours=10.0, base_days=14,
        fix=(
            "Ports:\n"
            "- Disable 110/143; keep only 993/995 (TLS).\n"
            "Auth hardening:\n"
            "- Disable plaintext auth; strong passwords; MFA/SSO if possible.\n"
            "Brute resistance:\n"
            "- Rate-limit; fail2ban; lockout thresholds.\n"
            "Monitoring:\n"
            "- Alert on ATO signals (impossible travel, spray patterns)."
        )
    ),

    
    Technique(
        id="T-MYSQL-EXPOSED",
        title="MySQL/MariaDB exposed to internet (data plane risk)",
        severity="HIGH",
        category="Data",
        family="DATA",
        applies=svc("mysql", {3306}),
        base_p=0.33, effort_hours=6.0, base_days=7,
        fix=(
            "Network:\n"
            "- DENY 3306 from internet; allow only private/VPN.\n"
            "Config:\n"
            "- bind-address to private interface; enforce TLS; least privilege.\n"
            "Secrets:\n"
            "- Rotate DB creds; remove unused accounts; audit grants.\n"
            "Detection:\n"
            "- Enable audit logs; alert on external connection attempts."
        )
    ),
    Technique(
        id="T-POSTGRES-EXPOSED",
        title="PostgreSQL exposed to internet",
        severity="HIGH",
        category="Data",
        family="DATA",
        applies=svc("postgresql", {5432}),
        base_p=0.30, effort_hours=7.0, base_days=7,
        fix=(
            "Network:\n"
            "- DENY 5432 from internet; private/VPN only.\n"
            "Auth:\n"
            "- SCRAM auth; strict pg_hba.conf; rotate creds.\n"
            "TLS:\n"
            "- Require TLS; log auth failures."
        )
    ),
    Technique(
        id="T-MONGODB-EXPOSED",
        title="MongoDB exposed to internet",
        severity="HIGH",
        category="Data",
        family="DATA",
        applies=svc("mongodb", {27017}),
        base_p=0.32, effort_hours=6.0, base_days=7,
        fix=(
            "Network:\n"
            "- DENY 27017 from internet; bind to private.\n"
            "Auth/TLS:\n"
            "- Require auth; enforce TLS; disable anonymous.\n"
            "Ops:\n"
            "- Backups; audit; allowlist only."
        )
    ),
    Technique(
        id="T-REDIS-EXPOSED",
        title="Redis exposed to internet",
        severity="HIGH",
        category="Data",
        family="DATA",
        applies=svc("redis", {6379}),
        base_p=0.36, effort_hours=5.0, base_days=5,
        fix=(
            "Network:\n"
            "- DENY 6379 from internet; internal-only.\n"
            "Hardening:\n"
            "- protected-mode yes; ACLs; requirepass.\n"
            "Risk reduction:\n"
            "- Disable/rename dangerous commands; TLS if supported."
        )
    ),
    Technique(
        id="T-ELASTIC-EXPOSED",
        title="Elasticsearch exposed",
        severity="HIGH",
        category="Data",
        family="DATA",
        applies=lambda h, s: (s.name in {"http", "https"} and s.port == 9200),
        base_p=0.34, effort_hours=5.0, base_days=5,
        fix=(
            "Network:\n"
            "- DENY 9200 from internet; put behind auth proxy.\n"
            "Security:\n"
            "- Enable authz/authn; TLS; restrict indices.\n"
            "Monitoring:\n"
            "- Audit access; alert on new index reads."
        )
    ),

    
    Technique(
        id="T-DOCKER-API-EXPOSED",
        title="Docker Remote API exposed",
        severity="HIGH",
        category="Infra",
        family="ORCH",
        applies=lambda h, s: (s.name in {"docker", "http", "https"} and s.port in {2375, 2376}),
        base_p=0.40, effort_hours=4.0, base_days=3,
        fix=(
            "Network:\n"
            "- Never expose 2375. Allow 2376 only with mTLS and allowlist.\n"
            "Config:\n"
            "- Bind to localhost; access via SSH tunnel/VPN.\n"
            "Ops:\n"
            "- Monitor daemon flags; alert on remote binds."
        )
    ),
    Technique(
        id="T-K8S-API-EXPOSED",
        title="Kubernetes API exposed",
        severity="HIGH",
        category="Infra",
        family="ORCH",
        applies=lambda h, s: (s.name in {"http", "https"} and s.port == 6443),
        base_p=0.30, effort_hours=8.0, base_days=7,
        fix=(
            "Network:\n"
            "- Restrict 6443 to control-plane/VPN only.\n"
            "Access:\n"
            "- RBAC least privilege; disable anonymous; rotate tokens/certs.\n"
            "Detection:\n"
            "- Audit logs + admission policies; alert on new cluster-admin binds."
        )
    ),
    Technique(
        id="T-RPC-EXPOSED",
        title="rpcbind exposed (RPC/NFS ecosystem risk)",
        severity="HIGH",
        category="Infra",
        family="INFRA",
        applies=svc("rpcbind", {111}),
        base_p=0.18, effort_hours=12.0, base_days=21,
        fix=(
            "Network:\n"
            "- Block 111/tcp+udp at perimeter.\n"
            "Architecture:\n"
            "- Keep RPC/NFS internal; allowlist trusted subnets only.\n"
            "Ops:\n"
            "- Inventory dependencies; monitor new RPC program registrations."
        )
    ),

    
    Technique(
        id="T-SNMP-EXPOSED",
        title="SNMP exposed (info disclosure / weak community risk)",
        severity="MED",
        category="Exposure",
        family="INFO",
        applies=svc("snmp", {161}),
        base_p=0.20, effort_hours=6.0, base_days=14,
        fix=(
            "Network:\n"
            "- Block 161 from internet.\n"
            "Protocol:\n"
            "- Prefer SNMPv3; disable public/private communities.\n"
            "Ops:\n"
            "- Allowlist NMS hosts only; monitor OID queries."
        )
    ),

    
    Technique(
        id="T-TCPWRAPPED-UNKNOWN",
        title="Unknown tcpwrapped service (needs identification)",
        severity="LOW",
        category="Exposure",
        family="UNKNOWN",
        applies=svc("tcpwrapped", None),
        base_p=0.06, effort_hours=3.0, base_days=30,
        fix="Identify service owner/purpose; close if unused; document and monitor."
    ),
]
