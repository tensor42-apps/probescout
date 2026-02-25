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
    os_guess: Optional[str] = None  # best OS match from nmap -O (e.g. "Linux 2.6.32 - 3.10")
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


def to_prompt_text(state: ScanState, last_plan: Optional[str] = None) -> str:
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
    if state.services:
        for port, proto, svc, ver in state.services:
            ver_str = f" {ver}" if ver else ""
            lines.append(f"  {port}/{proto}: {svc or 'unknown'}{ver_str}")
    if state.os_guess:
        lines.append(f"OS guess: {state.os_guess}")
    host_known = state.host_reachability != "unknown"
    any_port_scan_done = "port_scan" in state.scans_run
    services_known = "service_detect" in state.scans_run or "service_detect_common" in state.scans_run
    os_known = state.os_fingerprint_done
    lines.append(
        f"Goal progress: host_known={str(host_known).lower()} "
        f"port_scan_done={str(any_port_scan_done).lower()} "
        f"services_known={str(services_known).lower()} "
        f"os_known={str(os_known).lower()}"
    )
    n_open = len(state.open_ports)
    summary = f"Summary: {n_open} open port(s), services_known={str(services_known).lower()}, os_known={str(os_known).lower()}."
    lines.append(summary)
    lines.append("Scans run: " + ", ".join(state.scans_run) if state.scans_run else "Scans run: ")
    if state.host_reachability == "no_response" and "port_scan" not in state.scans_run:
        lines.append("Host discovery had no response; you may still try port_scan (e.g. firewall may block ping but leave ports open).")
    lines.append("For port_scan use \"range\" (e.g. \"1-1024\", \"22,80,443\", \"1-65535\").")
    if not state.open_ports:
        lines.append("service_detect and service_detect_common require open ports; with none, use \"done\" or run another port_scan.")
    if state.scans_run:
        lines.append("(You may choose 'done' to finish with current results, or continue.)")
    if last_plan:
        lines.append(f"Previous turn you said (plan): {last_plan}")
    return "\n".join(lines)


def update_from_nmap_xml(
    state: ScanState,
    action_id: str,
    xml_str: str,
    debug_path: Optional[str] = None,
) -> None:
    """Update state from nmap XML output. Namespace-agnostic tag names."""
    # We ran os_fingerprint; mark done regardless of XML so goal (see goal.py) can become achieved.
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
        # Parse best OS match from <host><os><osmatch name="..." accuracy="...">...
        for host in find_all(root, "host"):
            os_el = find_one(host, "os")
            if os_el is None:
                continue
            best_name: Optional[str] = None
            best_acc: int = -1
            for osmatch in find_all(os_el, "osmatch"):
                name = (osmatch.get("name") or "").strip()
                if not name:
                    continue
                try:
                    acc = int(osmatch.get("accuracy") or "0")
                except ValueError:
                    acc = 0
                if acc > best_acc:
                    best_acc = acc
                    best_name = name
            if best_name:
                state.os_guess = best_name
            break
        return

    if action_id == "port_scan":
        existing = set(state.open_ports)
        hosts = find_all(root, "host")
        if debug_path:
            try:
                with open(debug_path, "a", encoding="utf-8") as dbg:
                    dbg.write(f"[update_from_nmap_xml] len(hosts)={len(hosts)} root.tag={repr(root.tag)}\n")
            except OSError:
                pass
        for host in hosts:
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
                proto = (port_el.get("protocol") or "tcp").strip().lower() or "tcp"
                key = (port_num, proto)
                if key in existing:
                    continue
                state_el = find_one(port_el, "state")
                # Use "is not None": ET.Element with no children can be falsy (deprecated but still in 3.x)
                st = (state_el.get("state") or "").strip().lower() if state_el is not None else ""
                if debug_path and port_num in (22, 80):
                    try:
                        with open(debug_path, "a", encoding="utf-8") as dbg:
                            dbg.write(f"  port {portid} state_el.attrib={state_el.attrib if state_el is not None else None} st={repr(st)}\n")
                    except OSError:
                        pass
                if st == "open":
                    existing.add(key)
                    state.open_ports.append((port_num, proto))
        state.open_ports.sort(key=lambda x: (x[1], x[0]))
        return

    if action_id in ("service_detect", "service_detect_common"):
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


def format_nmap_xml_summary(xml_str: str, action_id: str) -> str:
    """Return a short human-readable summary of nmap XML output for UI display (no raw XML)."""
    if not xml_str or not xml_str.strip():
        if action_id == "host_reachability":
            return "No response."
        return "No output."
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return "Parse error."
    lines: List[str] = []

    def find_all(parent: ET.Element, local: str) -> List[ET.Element]:
        return [c for c in parent if _tag_local(c) == local]

    def find_one(parent: ET.Element, local: str) -> Optional[ET.Element]:
        for c in parent:
            if _tag_local(c) == local:
                return c
        return None

    if action_id == "host_reachability":
        hosts = find_all(root, "host")
        if not hosts:
            return "No response."
        host = hosts[0]
        status = find_one(host, "status")
        state_val = (status.get("state") or "").lower() if status else ""
        if state_val != "up":
            return "No response."
        addr = find_one(host, "address")
        addr_str = addr.get("addr", "") if addr and addr.get("addrtype") == "ipv4" else ""
        hostnames = find_one(host, "hostnames")
        name_str = ""
        if hostnames:
            hn = find_one(hostnames, "hostname")
            if hn and hn.get("name"):
                name_str = f" ({hn.get('name')})"
        return f"Host {addr_str}{name_str} is up."

    if action_id == "os_fingerprint":
        for host in find_all(root, "host"):
            os_el = find_one(host, "os")
            if os_el is None:
                continue
            best_name: Optional[str] = None
            best_acc = -1
            for osmatch in find_all(os_el, "osmatch"):
                name = (osmatch.get("name") or "").strip()
                if not name:
                    continue
                try:
                    acc = int(osmatch.get("accuracy") or "0")
                except ValueError:
                    acc = 0
                if acc > best_acc:
                    best_acc = acc
                    best_name = name
            if best_name:
                return f"OS: {best_name}"
            break
        return "OS fingerprint done (no match)."

    if action_id == "port_scan":
        for host in find_all(root, "host"):
            ports_el = find_one(host, "ports")
            if ports_el is None:
                continue
            open_ports: List[Tuple[int, str]] = []
            for port_el in find_all(ports_el, "port"):
                portid = port_el.get("portid")
                if not portid:
                    continue
                try:
                    port_num = int(portid)
                except ValueError:
                    continue
                proto = port_el.get("protocol", "tcp").lower()
                state_el = find_one(port_el, "state")
                st = (state_el.get("state") or "").lower() if state_el is not None else ""
                if st == "open":
                    open_ports.append((port_num, proto))
            open_ports.sort(key=lambda x: (x[1], x[0]))
            if open_ports:
                lines.append("Ports open: " + ", ".join(f"{p}/{pr}" for p, pr in open_ports))
            else:
                lines.append("No open ports in this range.")
            break
        return "\n".join(lines) if lines else "No ports."

    if action_id in ("service_detect", "service_detect_common"):
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
                disp = f"  {port_num}/{proto}: {svc_name or 'unknown'}"
                if version:
                    disp += f" {version}"
                lines.append(disp)
            break
        return "\n".join(lines) if lines else "No services."

    return "Done."
