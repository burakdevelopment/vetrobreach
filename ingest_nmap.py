from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List
from lxml import etree

@dataclass
class Service:
    port: int
    proto: str
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    tunnel: Optional[str] = None   

@dataclass
class Host:
    ip: str
    hostname: Optional[str]
    services: List[Service]

def parse_nmap_xml(path: str) -> list[Host]:
    tree = etree.parse(path)
    hosts: list[Host] = []

    for h in tree.findall(".//host"):
        addr = h.find(".//address[@addrtype='ipv4']")
        if addr is None:
            continue
        ip = addr.get("addr")

        hn = h.find(".//hostnames/hostname")
        hostname = hn.get("name") if hn is not None else None

        services: list[Service] = []
        for p in h.findall(".//ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue

            proto = (p.get("protocol") or "tcp").lower()
            portid = int(p.get("portid"))

            svc = p.find("service")
            if svc is None:
                services.append(Service(port=portid, proto=proto, name="unknown"))
                continue

            services.append(Service(
                port=portid,
                proto=proto,
                name=(svc.get("name") or "unknown").lower(),
                product=svc.get("product"),
                version=svc.get("version"),
                extrainfo=svc.get("extrainfo"),
                tunnel=svc.get("tunnel"),
            ))

        hosts.append(Host(ip=ip, hostname=hostname, services=services))
    return hosts
