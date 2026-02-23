"""
State model and prompt text for the agent loop. Implementation design §3, §10.
"""
from dataclasses import dataclass, field
from typing import List, Literal, Optional, Tuple
import xml.etree.ElementTree as ET


@dataclass
class ScanState:
    target: str
    host_reachability: Literal["unknown", "up", "no_response"] = "unknown"
    host_addr: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: List[Tuple[int, str]] = field(default_factory=list)
    services: List[Tuple[int, str, Optional[str], Optional[str]]] = field(default_factory=list)
    os_fingerprint_done: bool = False
    scans_run: List[str] = field(default_factory=list)
    nmap_run_count: int = 0

    @classmethod
    def initial(cls, target: str) -> "ScanState":
        return cls(
            target=target,
            host_reachability="unknown",
            host_addr=None,
            hostname=None,
            open_ports=[],
            services=[],
            os_fingerprint_done=False,
            scans_run=[],
            nmap_run_count=0,
        )


def _tag_local(elem: ET.Element) -> str:
    if elem.tag and "}" in elem.tag:
        return elem.tag.split("}", 1)[1]
    return elem.tag or ""


def goal_achieved(state: ScanState) -> bool:
    if state.host_reachability == "no_response":
        return True
    if state.host_reachability != "up":
        return False
    ports_known = (
        len(state.open_ports) > 0
        or "port_scan_1_100" in state.scans_run
        or "port_scan_1_1000" in state.scans_run
        or "port_scan_1_65535" in state.scans_run
    )
    services_known = "service_detect" in state.scans_run
    os_known = state.os_fingerprint_done
    return bool(ports_known and services_known and os_known)


def to_prompt_text(state: ScanState) -> str:
    lines = [
        f"Target: {state.target}",
        f"Host reachability: {state.host_reachability}",
    ]
    if state.host_addr:
        lines.append(f"Host address: {state.host_addr}")
    if state.hostname:
        lines.append(f"Hostname: {state.hostname}")
    if state.open_ports:
        ports_str = ", ".join(f"{p}/{proto}" for p, proto in state.open_ports)
        lines.append(f"Open ports: {ports_str}")
    else:
        lines.append("Open ports: none")
    for port, proto, svc, ver in state.services:
        ver_str = f" {ver}" if ver else ""
        lines.append(f"  {port}/{proto}: {svc or 'unknown'}{ver_str}")
    host_known = state.host_reachability != "unknown"
    ports_known = (
        len(state.open_ports) > 0
        or any(a in state.scans_run for a in ("port_scan_1_100", "port_scan_1_1000", "port_scan_1_65535"))
    )
    services_known = "service_detect" in state.scans_run
    os_known = state.os_fingerprint_done
    lines.append(
        f"Goal progress: host_known={str(host_known).lower()} "
        f"ports_known={str(ports_known).lower()} "
        f"services_known={str(services_known).lower()} "
        f"os_known={str(os_known).lower()}"
    )
    lines.append("Scans run: " + ", ".join(state.scans_run) if state.scans_run else "Scans run: ")
    return "\n".join(lines)


def update_from_nmap_xml(state: ScanState, action_id: str, xml_str: str) -> None:
    """Update state from nmap XML output. Namespace-agnostic tag names."""
    # We ran os_fingerprint; mark done regardless of XML so goal_achieved can become True.
    if action_id == "os_fingerprint":
        state.os_fingerprint_done = True
    if not xml_str or not xml_str.strip():
        if action_id == "host_reachability":
            state.host_reachability = "no_response"
        return
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        if action_id == "host_reachability":
            state.host_reachability = "no_response"
        return

    def find_all(parent: ET.Element, local: str) -> List[ET.Element]:
        out: List[ET.Element] = []
        for c in parent:
            if _tag_local(c) == local:
                out.append(c)
        return out

    def find_one(parent: ET.Element, local: str) -> Optional[ET.Element]:
        for c in parent:
            if _tag_local(c) == local:
                return c
        return None

    def text_of(e: Optional[ET.Element], default: str = "") -> str:
        return (e.text or "").strip() if e is not None else default

    if action_id == "host_reachability":
        hosts = find_all(root, "host")
        if not hosts:
            state.host_reachability = "no_response"
            return
        host = hosts[0]
        status = find_one(host, "status")
        state_val = (status.get("state") or "").lower() if status is not None else ""
        state.host_reachability = "up" if state_val == "up" else "no_response"
        addr = find_one(host, "address")
        if addr is not None and addr.get("addrtype") == "ipv4":
            state.host_addr = addr.get("addr")
        hostnames = find_one(host, "hostnames")
        if hostnames:
            hn = find_one(hostnames, "hostname")
            if hn is not None and hn.get("name"):
                state.hostname = hn.get("name")
        return

    if action_id == "os_fingerprint":
        state.os_fingerprint_done = True
        return

    if action_id in ("port_scan_1_100", "port_scan_1_1000", "port_scan_1_65535"):
        existing = set(state.open_ports)
        for host in find_all(root, "host"):
            ports_el = find_one(host, "ports")
            if ports_el is None:
                continue
            for port_el in find_all(ports_el, "port"):
                portid = port_el.get("portid")
                if not portid:
                    continue
                try:
                    port_num = int(portid)
                except ValueError:
                    continue
                proto = port_el.get("protocol", "tcp").lower()
                key = (port_num, proto)
                if key in existing:
                    continue
                state_el = find_one(port_el, "state")
                st = (state_el.get("state") or "").lower() if state_el else ""
                if st == "open":
                    existing.add(key)
                    state.open_ports.append((port_num, proto))
        state.open_ports.sort(key=lambda x: (x[1], x[0]))
        return

    if action_id == "service_detect":
        for host in find_all(root, "host"):
            ports_el = find_one(host, "ports")
            if ports_el is None:
                continue
            for port_el in find_all(ports_el, "port"):
                portid = port_el.get("portid")
                if not portid:
                    continue
                try:
                    port_num = int(portid)
                except ValueError:
                    continue
                proto = port_el.get("protocol", "tcp").lower()
                svc_el = find_one(port_el, "service")
                svc_name = svc_el.get("name") if svc_el is not None else None
                product = svc_el.get("product") if svc_el is not None else None
                version = svc_el.get("version") if svc_el is not None else None
                if product and not svc_name:
                    svc_name = product
                state.services.append((port_num, proto, svc_name or None, version or None))
        state.services.sort(key=lambda x: (x[1], x[0]))
        return
