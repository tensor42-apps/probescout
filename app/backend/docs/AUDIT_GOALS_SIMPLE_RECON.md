# Audit: Simple recon and “Summary: 0 open port(s)”

## Why does Simple recon run the port scan in the next step?

**By design.** For **simple_recon** the flow is:

1. **Step 1:** LLM proposes `host_reachability` → we run `nmap -sn` (no sudo). State: host up, address/hostname set, open ports still none.
2. **Step 2:** We send that state back; LLM proposes `port_scan` with e.g. `range: 1-1024` → we run `sudo -n /usr/bin/nmap -sS -p 1-1024 ...`.
3. **Step 3:** We send the new state; if there are open ports, LLM may do service_detect / os_fingerprint; if not, LLM says `done`.

So **running the port scan in the “next step” after host_reachability is correct.** The goal text allows host_reachability, port_scan, service_detect, os_fingerprint, done; the model chose host_reachability then port_scan. No bug there.

## Why does the log show “Summary: 0 open port(s)” after the port scan?

The **Summary** line in the LLM prompt comes from `state.open_ports`:

- `Summary: {n_open} open port(s), services_known=..., os_known=....`
- So “0 open port(s)” means **no ports were added to state** after the port scan.

That happens when:

1. **Port scan fails before producing XML** (e.g. `sudo: a password is required`). Then `run_nmap` gets no or invalid stdout; we call `update_from_nmap_xml(state, "port_scan", xml_out or "")` with empty or non-XML. We return early and never append to `state.open_ports`, so it stays empty. We still append `"port_scan"` to `state.scans_run`, so the next prompt correctly shows `port_scan_done=true` and `Summary: 0 open port(s)`.
2. **Port scan succeeds but finds no open ports.** Then XML has no `<port state="open">` and we again end up with 0 open ports.

So **the log is consistent**: we did run a port_scan (hence `port_scan_done=true`), but we got **no open ports in state** because either the scan failed (e.g. sudo) or the target had no open ports in that range. In the run you had with “sudo: a password required”, the port scan failed, so 0 open ports is expected.

After the **sudo fix** (no stdbuf when using sudo), the same Simple recon run should get valid XML from nmap; for scanme.nmap.org you should then see e.g. `Summary: 2 open port(s)` (22, 80) and the LLM can continue with service_detect / os_fingerprint or done as appropriate.

## Summary

| Question | Answer |
|----------|--------|
| Why run port scan in the “next step”? | Simple recon is host_reachability → port_scan → …; the next step after host_reachability is port_scan. Correct. |
| Why “Summary: 0 open port(s)”? | Port scan either failed (e.g. sudo) so no XML was parsed, or succeeded with no open ports. State reflects that; after the sudo fix, a new run should show real open ports when nmap succeeds. |
