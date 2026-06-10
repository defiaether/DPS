# DPS (Dynamic-Port-Shield) 
Secure your VPS ports using web-based dynamic IP whitelisting and auto-expiring firewall rules.

# Dynamic Port Shield (Berayan SPA)

# Dynamic Port Shield (Berayan SPA)

A lightweight, terminal-guided port authorization system (SPA alternative) for Linux servers. It helps protect your VPN ports (such as X-UI/Sanaei, Shadowsocks, VMess) by keeping them closed by default and dynamically opening them only for authorized client IPs.

---

## 🛡️ Key Features

*   **Default-Drop Security:** All specified VPN/service ports are completely blocked (`DROP` policy) to the public by default.
*   **Web-Based IP Activation:** Clients authorize their current IP address simply by visiting a personalized web link in any browser.
*   **User & Token Management:** Admin can generate, list, and delete unique user tokens directly from an interactive Terminal User Interface (TUI).
*   **Automatic 48-Hour Lease Expiration:** Whitelisted IPs are automatically removed from the firewall after 48 hours.
*   **Reboot Resilient:** Active leases are preserved in a lightweight SQLite database and re-applied to `iptables` if the server reboots.
*   **Minimal Dependencies:** Designed for Ubuntu, using standard Python 3 and native `iptables` without heavy system overhead.

---

## ⚙️ System Architecture

The project works by combining a Python web service, a local SQLite database, and the native Linux kernel firewall (`iptables`).

```
  [ Client IP ] ----( Visits Secure Link )----> [ Python Web Server ]
                                                       |
                                            [ Validates Token in DB ]
                                                       |
  [ Port Opened ] <---( Inserts IP into Chain )<--[ Valid Token? ]
   (For 48 Hours)       "iptables -I BERAYAN-SPA"
```

1. **Firewall Isolation:** Upon installation, the script creates a dedicated `iptables` chain called `BERAYAN-SPA`. All traffic directed to your VPN ports is routed through this chain. If an IP is not found in the chain, the traffic is dropped.
2. **The Verification Process:** When a user opens `http://<vps-ip>:<port>/auth?key=<unique_token>` in their browser, the background Python service verifies the token against the SQLite database (`spa.db`).
3. **Lease Allocation:** If the token is valid, the Python service fetches the client's public IP (supporting proxy headers like Cloudflare's `CF-Connecting-IP` if placed behind a CDN) and registers it in the DB with a 48-hour expiry timestamp. It then appends an `ACCEPT` rule in the `BERAYAN-SPA` chain for that specific IP.
4. **Auto-Expiration:** A background thread inside the daemon runs a cleanup cycle every 60 seconds, gracefully removing expired IPs from both the database and `iptables`.

---

## 🚀 Quick Installation & Management

Run the following command as **root** to install, reconfigure, or manage your users:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/defiaether/dps/main/install.sh)
```

### Prerequisites
*   Ubuntu 20.04 LTS or newer (tested).
*   Root access to the VPS.
*   Ports to be protected (e.g., your X-UI inbound ports) must already be configured on your VPN panel.

---

## 🛠️ Usage Guide

### 1. Administration Menu
Once you run the script, an interactive menu will appear in your terminal:

```
------------------------------------------------
       Berayan - Port Authorization System      
------------------------------------------------
Service Status: Active (Running)
------------------------------------------------
1) Install / Reconfigure Ports
2) User Management (Add/List/Delete Links)
3) System Status & Config Overview
4) List Active Whitelisted IPs
5) Completely Uninstall
6) Exit
------------------------------------------------
```

*   **Add New User:** Generates a secure, unique 12-character token and outputs the client's personalized authorization URL.
*   **List Active Whitelisted IPs:** Shows currently authorized IP addresses, the user they belong to, exact expiry time, and remaining hours.
*   **Delete User:** Revokes a token. Any active IP lease belonging to this user is immediately removed and blocked from the firewall.

### 2. Client Side
Simply send the generated link to your client:
`http://<SERVER_IP>:<WEB_PORT>/auth?key=<UNIQUE_TOKEN>`

When they open it on their phone or PC (while connected to their local network without any active VPN), they will see an **Access Authorized** web page. They can then immediately connect to your VPN service.

---

## ⚠️ Important Considerations

*   **Local Network Changes:** If a client switches networks (e.g., from home Wi-Fi to mobile data), their public IP will change, and they must click the link again to authorize the new IP.
*   **CDN/Reverse Proxy:** If you place the web authorization port behind Cloudflare or another reverse proxy, the Python backend is pre-configured to check for standard headers like `CF-Connecting-IP` and `X-Forwarded-For` to retrieve the correct client IP.
*   **UFW / Firewalls:** If you use `ufw` alongside raw `iptables`, ensure that `ufw` does not conflict with the custom `BERAYAN-SPA` chain.

---

## 📄 License
This project is open-source. Use it at your own discretion to improve your server security posture.
