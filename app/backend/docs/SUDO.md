# Fix “sudo: a password is required” for nmap (Linux)

ProbeScout runs TCP SYN scans (`nmap -sS`) which need root. The backend runs `sudo -n /path/to/nmap ...` (full path so it matches sudoers) and **must** have passwordless sudo for that binary only (no need to run the whole app as root).

## Fix permanently

1. **Choose the nmap binary** your backend uses:
   ```bash
   which nmap
   ```
   Example: `/usr/bin/nmap` or `/usr/local/bin/nmap`.

2. **Create a sudoers fragment** (use `sudo`):
   ```bash
   sudo visudo -f /etc/sudoers.d/probescout
   ```
   Add one line (replace `YOUR_USER` and `/usr/bin/nmap` if different):
   ```
   YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/nmap
   ```
   Save and exit. Use the **exact path** from `which nmap`.

3. **Set safe permissions**:
   ```bash
   sudo chmod 440 /etc/sudoers.d/probescout
   ```

4. **Test** (no password should be asked):
   ```bash
   sudo -n nmap --version
   ```

5. **Start the backend** as your normal user (do not run the app with sudo).

If the backend still reports “password required”, ensure the path in sudoers matches the `nmap` used by the process (same PATH when the server runs). The backend runs `sudo -n /usr/bin/nmap ...` with **nmap as the direct command** (no wrapper like stdbuf), so your NOPASSWD rule for `/usr/bin/nmap` applies.
