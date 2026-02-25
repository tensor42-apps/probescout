# ProbeScout goals

Single source of truth for scan goals. **Goal name** is shown in the UI dropdown; **goal description** is for documentation and can be expanded. Implementation: `goal.py` (GOALS).

---

## Implemented

| id | name (UI) | description |
|----|-----------|-------------|
| `simple_recon` | Simple recon scan | Do a simple recon on the target. LLM decides steps and approach (host check, port scan, service detection, OS as needed). |
| `well_known_tcp` | Well known TCP scan | TCP port scan over well-known ports (typically 1-1024). **No host_reachability**; go straight to port_scan. LLM chooses exact range(s). |
| `full_stealth_tcp` | Full Stealth TCP scan on all ports | Full stealth TCP scan across all ports. **No host_reachability**; go straight to port_scan. No OS/service required to finish. |
| `quick_top_ports` | Quick top ports | Small, fixed set of high-value ports (e.g. 22, 80, 443, 21, 25, 53, 8080, 8443, 3389). Fast first look; optional service_detect. Port-scan goal. |
| `common_ports` | Common service ports | Common service ports (FTP 21, SSH 22, SMTP 25, DNS 53, HTTP 80, POP3 110, IMAP 143, HTTPS 443, 8080, 8443) + service detection. Port-scan goal; achieved when port_scan + service_detect. |
| `web_ports` | Web server ports | Web ports only (80, 443, 8080, 8443, 8000, 8888) + service detection. Identify web stack. Port-scan goal; achieved when port_scan + service_detect. |
| `compliance_ports` | Policy / compliance ports | Fixed policy set (e.g. 22, 80, 443, 3389, 5985) + version detection. Port-scan goal; achieved when port_scan + service_detect. |
| `external_perimeter` | External perimeter recon | Simulate external attacker: host reachability → port scan → service_detect → os_fingerprint. Full intents; achieved_when: full. |

---

## Future

Add new rows above and implement in `goal.py` (GOALS + PORT_SCAN_GOAL_IDS if port-scan-only, and `achieved_when`).

---

## When is the goal achieved? (`achieved_when` in goal.py)

| value | meaning |
|-------|--------|
| `full` | Host no_response → stop. Host up → service_detect + os_fingerprint done. Used for simple_recon, well_known_tcp, external_perimeter. |
| `port_scan_only` | Host no_response → **still run at least one port_scan** (ping may be blocked but ports open), then stop. Host up → one port_scan run then stop. No OS/service required. Used for full_stealth_tcp, quick_top_ports. |
| `port_scan_and_services` | Port_scan + (service_detect or service_detect_common) required. No OS required. Used for common_ports, web_ports, compliance_ports. |

So for **full_stealth_tcp** and **quick_top_ports**: if ping is blocked we do **not** stop until we've run a port_scan. For **port_scan_and_services** goals we run port_scan then service_detect (open ports may be empty; service_detect still runs).

---

## Conventions

- **id**: lowercase, snake_case; used in API and config.
- **name (UI)**: short label for the dropdown only.
- **description**: one line or more; used in docs and to derive prompt text in `goal.py` when implementing.
- **Intents**: simple_recon and external_perimeter use `host_reachability`, `port_scan`, `service_detect`, `os_fingerprint`, `done`. **Port-scan goals** (well_known_tcp, full_stealth_tcp, quick_top_ports, common_ports, web_ports, compliance_ports) do **not** use host_reachability: intents are `port_scan`, `service_detect`, `os_fingerprint`, `done` only. Cooling between nmap runs is **backend policy** (config: `cooling`, `cooling_seconds`), not an LLM intent.
- **Stopping**: We stop as soon as the LLM returns intent **done** (or when the goal is achieved, or on error). `max_steps` (e.g. 30) is only a safety cap on LLM turns, not a target.
