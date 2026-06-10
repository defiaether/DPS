#!/bin/bash

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
YELLOW='\033[1;33m'

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this script as root (sudo).${NC}"
  exit 1
fi

# Directory structure
INSTALL_DIR="/opt/berayan-spa"
CONFIG_FILE="$INSTALL_DIR/config.env"
DB_FILE="$INSTALL_DIR/spa.db"
PYTHON_APP="$INSTALL_DIR/app.py"
SERVICE_FILE="/etc/systemd/system/berayan-spa.service"

mkdir -p "$INSTALL_DIR"

# ASCII Art Header
show_header() {
  clear
  echo -e "${GREEN}"
  echo " ____  _____ ____    _YA_   _   _      "
  echo "| __ )| ____|  _ \  / \ \ \ / / / \  | \ | |"
  echo "|  _ \|  _| | |_) |/ _ \ \ V / / _ \ |  \| |"
  echo "| |_) | |___|  _ < / ___ \ | |/ ___ \| |\  |"
  echo "|____/|_____|_| \_/_/   \_\_/_/   \_\_| \_|"
  echo -e "${NC}"
  echo "------------------------------------------------"
  echo "       Berayan - Port Authorization System      "
  echo "------------------------------------------------"
}

# Function to detect Server Public IP
get_public_ip() {
  local ip
  ip=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me)
  if [ -z "$ip" ]; then
    ip=$(hostname -I | awk '{print $1}')
  fi
  echo "$ip"
}

# Install dependencies if missing
install_dependencies() {
  echo -e "${YELLOW}Checking dependencies...${NC}"
  apt-get update -y > /dev/null 2>&1
  apt-get install -y python3 iptables sqlite3 curl > /dev/null 2>&1
}

# Save configuration
save_config() {
  cat <<EOF > "$CONFIG_FILE"
VPN_PORTS=$1
WEB_PORT=$2
SERVER_IP=$3
EOF
}

# Read configuration if exists
load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
  fi
}

# Create the Python Backend Web Service
create_python_app() {
  cat << 'EOF' > "$PYTHON_APP"
import http.server
import socketserver
import sqlite3
import os
import subprocess
import sys
import time
import threading
from urllib.parse import urlparse, parse_qs

# Read environment variables
CONFIG_FILE = "/opt/berayan-spa/config.env"
config = {}
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE) as f:
        for line in f:
            if "=" in line:
                name, value = line.strip().split("=", 1)
                config[name] = value

VPN_PORTS = config.get("VPN_PORTS", "")
WEB_PORT = int(config.get("WEB_PORT", "8080"))
DB_PATH = "/opt/berayan-spa/spa.db"

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            token TEXT UNIQUE,
            created_at INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS authorized_ips (
            ip TEXT PRIMARY KEY,
            username TEXT,
            expiry INTEGER
        )
    """)
    conn.commit()
    conn.close()

# IPTables control wrapper
def manage_iptables(action, ip):
    """action: -I (Insert) or -D (Delete)"""
    if not VPN_PORTS:
        return
    for proto in ["tcp", "udp"]:
        # Delete first to prevent duplicate rules
        subprocess.run(
            f"iptables -D BERAYAN-SPA -s {ip} -p {proto} -m multiport --dports {VPN_PORTS} -j ACCEPT",
            shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
        )
        if action == "-I":
            subprocess.run(
                f"iptables -I BERAYAN-SPA -s {ip} -p {proto} -m multiport --dports {VPN_PORTS} -j ACCEPT",
                shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
            )

# Setup initial firewall chains
def setup_firewall_base():
    if not VPN_PORTS:
        return
    # Create BERAYAN-SPA chain if not exists
    subprocess.run("iptables -N BERAYAN-SPA", shell=True, stderr=subprocess.DEVNULL)
    
    # Flush existing rules in the chain
    subprocess.run("iptables -F BERAYAN-SPA", shell=True)

    # Clean legacy rules in INPUT
    subprocess.run(f"iptables -D INPUT -p tcp -m multiport --dports {VPN_PORTS} -j BERAYAN-SPA", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run(f"iptables -D INPUT -p udp -m multiport --dports {VPN_PORTS} -j BERAYAN-SPA", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run(f"iptables -D INPUT -p tcp -m multiport --dports {VPN_PORTS} -j DROP", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run(f"iptables -D INPUT -p udp -m multiport --dports {VPN_PORTS} -j DROP", shell=True, stderr=subprocess.DEVNULL)

    # Insert jumps to the BERAYAN-SPA chain
    subprocess.run(f"iptables -A INPUT -p tcp -m multiport --dports {VPN_PORTS} -j BERAYAN-SPA", shell=True)
    subprocess.run(f"iptables -A INPUT -p udp -m multiport --dports {VPN_PORTS} -j BERAYAN-SPA", shell=True)
    
    # Drop all other traffic to those ports
    subprocess.run(f"iptables -A INPUT -p tcp -m multiport --dports {VPN_PORTS} -j DROP", shell=True)
    subprocess.run(f"iptables -A INPUT -p udp -m multiport --dports {VPN_PORTS} -j DROP", shell=True)

# Restore rules from DB on startup
def restore_rules():
    setup_firewall_base()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = int(time.time())
    cursor.execute("SELECT ip FROM authorized_ips WHERE expiry > ?", (now,))
    ips = cursor.fetchall()
    for (ip,) in ips:
        manage_iptables("-I", ip)
    conn.close()

# Background cleanup thread
def cleanup_loop():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            now = int(time.time())
            # Find expired
            cursor.execute("SELECT ip FROM authorized_ips WHERE expiry <= ?", (now,))
            expired = cursor.fetchall()
            for (ip,) in expired:
                manage_iptables("-D", ip)
                print(f"[Cleanup] IP {ip} expired and blocked.")
            
            # Delete expired from DB
            cursor.execute("DELETE FROM authorized_ips WHERE expiry <= ?", (now,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Cleanup Error] {e}", file=sys.stderr)
        time.sleep(60)

# HTTP Request Handler
class SPAHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed_url = urlparse(self.path)
        query = parse_qs(parsed_url.query)
        
        if parsed_url.path == "/auth":
            token_received = query.get("key", [None])[0]
            if not token_received:
                self.send_response(400)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Bad Request: Missing Token Key")
                return

            # Check database for valid user token
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE token = ?", (token_received,))
            user_row = cursor.fetchone()

            if user_row:
                username = user_row[0]
                # Handle Reverse Proxy headers if behind Cloudflare/Nginx, otherwise use direct IP
                client_ip = self.headers.get("CF-Connecting-IP") or \
                            self.headers.get("X-Forwarded-For") or \
                            self.client_address[0]
                
                # Normalize IPv6 mapped IPv4 addresses if necessary
                if client_ip.startswith("::ffff:"):
                    client_ip = client_ip[7:]

                expiry_time = int(time.time()) + (48 * 3600) # 48 hours

                try:
                    cursor.execute("INSERT OR REPLACE INTO authorized_ips (ip, username, expiry) VALUES (?, ?, ?)", (client_ip, username, expiry_time))
                    conn.commit()
                    conn.close()

                    manage_iptables("-I", client_ip)

                    self.send_response(200)
                    self.send_header("Content-type", "text/html; charset=utf-8")
                    self.end_headers()
                    
                    html_response = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Access Granted</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <style>
                            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; text-align: center; background: #121212; color: #e0e0e0; padding: 50px 20px; }}
                            .container {{ max-width: 500px; margin: auto; background: #1e1e1e; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); border: 1px solid #333; }}
                            h1 {{ color: #4caf50; font-size: 24px; }}
                            p {{ font-size: 16px; line-height: 1.6; color: #b0b0b0; }}
                            .ip-badge {{ display: inline-block; background: #2e7d32; color: #fff; padding: 8px 16px; border-radius: 6px; font-weight: bold; margin: 15px 0; font-family: monospace; font-size: 18px; }}
                            .username-label {{ color: #2196f3; font-weight: bold; }}
                            .footer {{ font-size: 12px; color: #777; margin-top: 30px; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>Access Authorized</h1>
                            <p>Hello <span class="username-label">{username}</span>, your IP address has been granted temporary access to the services.</p>
                            <div class="ip-badge">{client_ip}</div>
                            <p>This authorization is valid for <b>48 hours</b>. After expiration, you will need to open your specific link again.</p>
                            <div class="footer">Berayan SPA System</div>
                        </div>
                    </body>
                    </html>
                    """
                    self.wfile.write(html_response.encode("utf-8"))
                except Exception as e:
                    self.send_error(500, f"Database/IPtables error: {e}")
            else:
                conn.close()
                self.send_response(403)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Forbidden: Invalid Security Token")
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

if __name__ == "__main__":
    init_db()
    restore_rules()
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()
    
    # Run Web Server
    server_address = ("", WEB_PORT)
    try:
        with socketserver.TCPServer(server_address, SPAHandler) as httpd:
            print(f"Auth server started on port {WEB_PORT}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
EOF
  chmod +x "$PYTHON_APP"
}

# Create Systemd Service File
create_service() {
  cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Berayan Single Packet Authorization Web Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $PYTHON_APP
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable berayan-spa.service > /dev/null 2>&1
}

# Install or Update Function
install_spa() {
  show_header
  install_dependencies

  # Get inputs
  echo -e "${YELLOW}Step 1: VPN Ports Setup${NC}"
  echo "Please enter the VPN ports you want to protect (e.g. 443,2053,10443)."
  echo "If you have multiple ports, separate them with a comma (no spaces)."
  read -p "Ports: " USER_PORTS
  
  # Clean input spaces
  USER_PORTS=$(echo "$USER_PORTS" | tr -d ' ')

  if [[ ! "$USER_PORTS" =~ ^[0-9,]+$ ]]; then
    echo -e "${RED}Invalid input. Only numbers and commas are allowed.${NC}"
    read -p "Press Enter to try again..."
    return
  fi

  echo -e "\n${YELLOW}Step 2: Web Authorization Port Setup${NC}"
  read -p "Enter a port for the Authorization Web Link [Default: 8080]: " WEB_PORT
  WEB_PORT=${WEB_PORT:-8080}

  SERVER_IP=$(get_public_ip)

  # Save variables
  save_config "$USER_PORTS" "$WEB_PORT" "$SERVER_IP"

  # Create application and register service
  create_python_app
  create_service

  # Initialize DB from python app immediately
  /usr/bin/python3 -c "import sys; sys.path.append('$INSTALL_DIR'); import app; app.init_db()"

  # Start/Restart Service
  systemctl restart berayan-spa.service

  show_header
  echo -e "${GREEN}Installation / Configuration completed successfully!${NC}"
  echo -e "Protected VPN Ports:   ${YELLOW}$USER_PORTS${NC}"
  echo -e "Web Authorization Port: ${YELLOW}$WEB_PORT${NC}"
  echo ""
  echo -e "System is ready. Now you can go to 'User Management' from the main menu to create user links."
  echo ""
  read -p "Press Enter to return to main menu..."
}

# User Management Menu
manage_users() {
  while true; do
    show_header
    load_config
    if [ -z "$VPN_PORTS" ]; then
      echo -e "${RED}Please run installation/configuration first!${NC}"
      read -p "Press Enter to continue..."
      break
    fi

    echo -e "${GREEN}User Management:${NC}"
    echo "------------------------------------------------"
    echo "1) Add New User (Generate Token Link)"
    echo "2) List All Users & Access Links"
    echo "3) Delete User"
    echo "4) Back to Main Menu"
    echo "------------------------------------------------"
    read -p "Select an option [1-4]: " USER_OPTION

    case $USER_OPTION in
      1)
        show_header
        echo -e "${YELLOW}Add New User${NC}"
        read -p "Enter username (alphanumeric, no spaces): " NEW_USER
        
        # Validate username
        if [[ ! "$NEW_USER" =~ ^[a-zA-Z0-9_-]+$ ]]; then
          echo -e "${RED}Invalid username. Use only alphanumeric characters, underscores, or hyphens.${NC}"
          read -p "Press Enter to continue..."
          continue
        fi

        # Check if user already exists
        EXISTS=$(sqlite3 "$DB_FILE" "SELECT 1 FROM users WHERE username='$NEW_USER';")
        if [ "$EXISTS" == "1" ]; then
          echo -e "${RED}User already exists!${NC}"
          read -p "Press Enter to continue..."
          continue
        fi

        # Generate unique token
        NEW_TOKEN=$(openssl rand -hex 12)
        sqlite3 "$DB_FILE" "INSERT INTO users (username, token, created_at) VALUES ('$NEW_USER', '$NEW_TOKEN', strftime('%s','now'));"
        
        echo -e "\n${GREEN}User added successfully!${NC}"
        echo -e "Username:    ${YELLOW}$NEW_USER${NC}"
        echo -e "Access Link: ${GREEN}http://$SERVER_IP:$WEB_PORT/auth?key=$NEW_TOKEN${NC}"
        echo ""
        read -p "Press Enter to continue..."
        ;;
      2)
        show_header
        echo -e "${GREEN}All Active Users & Links:${NC}"
        echo "------------------------------------------------"
        USER_COUNT=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM users;")
        if [ "$USER_COUNT" -eq 0 ]; then
          echo -e "${YELLOW}No users found. Create one first.${NC}"
        else
          sqlite3 "$DB_FILE" "SELECT username, token FROM users;" | while read -r row; do
            if [ -n "$row" ]; then
              u_name=$(echo "$row" | cut -d'|' -f1)
              u_tok=$(echo "$row" | cut -d'|' -f2)
              echo -e "User: ${YELLOW}$u_name${NC}"
              echo -e "Link: ${GREEN}http://$SERVER_IP:$WEB_PORT/auth?key=$u_tok${NC}"
              echo "------------------------------------------------"
            fi
          done
        fi
        read -p "Press Enter to continue..."
        ;;
      3)
        show_header
        echo -e "${RED}Delete User${NC}"
        echo "------------------------------------------------"
        USER_COUNT=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM users;")
        if [ "$USER_COUNT" -eq 0 ]; then
          echo -e "${YELLOW}No users found to delete.${NC}"
          read -p "Press Enter to continue..."
          continue
        fi

        sqlite3 "$DB_FILE" "SELECT username FROM users;" | while read -r u_name; do
          echo "- $u_name"
        done
        echo "------------------------------------------------"
        read -p "Enter username to delete: " DEL_USER

        # Verify existence
        EXISTS=$(sqlite3 "$DB_FILE" "SELECT 1 FROM users WHERE username='$DEL_USER';")
        if [ "$EXISTS" != "1" ]; then
          echo -e "${RED}User not found!${NC}"
          read -p "Press Enter to continue..."
          continue
        fi

        # Remove active IP authorization from IPTables for this user
        sqlite3 "$DB_FILE" "SELECT ip FROM authorized_ips WHERE username='$DEL_USER';" | while read -r ip; do
          if [ -n "$ip" ]; then
            for proto in tcp udp; do
              iptables -D BERAYAN-SPA -s "$ip" -p "$proto" -m multiport --dports "$VPN_PORTS" -j ACCEPT 2>/dev/null
            done
          fi
        done

        # Remove from Database
        sqlite3 "$DB_FILE" "DELETE FROM authorized_ips WHERE username='$DEL_USER';"
        sqlite3 "$DB_FILE" "DELETE FROM users WHERE username='$DEL_USER';"

        echo -e "${GREEN}User $DEL_USER and their active IP access have been successfully removed.${NC}"
        read -p "Press Enter to continue..."
        ;;
      4)
        break
        ;;
      *)
        echo -e "${RED}Invalid Option!${NC}"
        sleep 1
        ;;
    esac
  done
}

# Show configuration and general status
show_status() {
  show_header
  load_config
  if [ -z "$VPN_PORTS" ]; then
    echo -e "${RED}System is not configured yet. Please run Install first.${NC}"
  else
    USER_COUNT=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM users;")
    ACTIVE_COUNT=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM authorized_ips WHERE expiry > strftime('%s','now');")
    
    echo -e "${GREEN}System Status Overview:${NC}"
    echo "------------------------------------------------"
    echo -e "Protected VPN Ports:   ${YELLOW}$VPN_PORTS${NC}"
    echo -e "Web Interface Port:   ${YELLOW}$WEB_PORT${NC}"
    echo -e "Server Public IP:     ${YELLOW}$SERVER_IP${NC}"
    echo -e "Total Created Users:  ${YELLOW}$USER_COUNT${NC}"
    echo -e "Active Whitelisted IPs: ${YELLOW}$ACTIVE_COUNT${NC}"
    echo "------------------------------------------------"
    echo -e "Go to 'User Management' to view individual access links."
  fi
  echo ""
  read -p "Press Enter to return to main menu..."
}

# List currently whitelisted IPs
list_ips() {
  show_header
  if [ ! -f "$DB_FILE" ]; then
    echo -e "${RED}Database not found. Please complete the installation first.${NC}"
  else
    echo -e "${GREEN}Currently Whitelisted Client IPs:${NC}"
    echo "------------------------------------------------"
    printf "%-15s | %-12s | %-19s | %-12s\n" "Client IP" "User" "Expiry Date" "Time Left"
    echo "------------------------------------------------"
    
    # Query Database
    sqlite3 "$DB_FILE" "SELECT ip, username, expiry FROM authorized_ips;" | while read -r row; do
      if [ -n "$row" ]; then
        ip=$(echo "$row" | cut -d'|' -f1)
        user=$(echo "$row" | cut -d'|' -f2)
        expiry=$(echo "$row" | cut -d'|' -f3)
        now=$(date +%s)
        diff=$((expiry - now))
        
        if [ $diff -gt 0 ]; then
          hours=$((diff / 3600))
          minutes=$(( (diff % 3600) / 60 ))
          rem_time="${hours}h ${minutes}m"
          expiry_date=$(date -d @"$expiry" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -r "$expiry" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
          printf "%-15s | %-12s | %-19s | %-12s\n" "$ip" "$user" "$expiry_date" "$rem_time"
        fi
      fi
    done
  fi
  echo ""
  read -p "Press Enter to return to main menu..."
}

# Completely remove the application
uninstall_spa() {
  show_header
  read -p "Are you sure you want to completely uninstall Berayan SPA? (y/n): " confirm
  if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
    echo -e "${YELLOW}Stopping and disabling service...${NC}"
    systemctl stop berayan-spa.service > /dev/null 2>&1
    systemctl disable berayan-spa.service > /dev/null 2>&1
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload

    load_config
    if [ -n "$VPN_PORTS" ]; then
      echo -e "${YELLOW}Cleaning up IPTables rules...${NC}"
      # Remove jumps
      iptables -D INPUT -p tcp -m multiport --dports "$VPN_PORTS" -j BERAYAN-SPA > /dev/null 2>&1
      iptables -D INPUT -p udp -m multiport --dports "$VPN_PORTS" -j BERAYAN-SPA > /dev/null 2>&1
      # Remove block drops
      iptables -D INPUT -p tcp -m multiport --dports "$VPN_PORTS" -j DROP > /dev/null 2>&1
      iptables -D INPUT -p udp -m multiport --dports "$VPN_PORTS" -j DROP > /dev/null 2>&1
      # Remove chain
      iptables -F BERAYAN-SPA > /dev/null 2>&1
      iptables -X BERAYAN-SPA > /dev/null 2>&1
    fi

    echo -e "${YELLOW}Removing installation files...${NC}"
    rm -rf "$INSTALL_DIR"

    echo -e "${GREEN}Berayan SPA has been successfully uninstalled.${NC}"
  else
    echo -e "${YELLOW}Uninstall cancelled.${NC}"
  fi
  sleep 2
}

# Main Execution Loop
while true; do
  show_header
  load_config
  
  # Status indicator
  if systemctl is-active --quiet berayan-spa.service; then
    echo -e "Service Status: ${GREEN}Active (Running)${NC}"
  else
    echo -e "Service Status: ${RED}Inactive (Not Installed/Stopped)${NC}"
  fi
  echo "------------------------------------------------"
  echo "1) Install / Reconfigure Ports"
  echo "2) User Management (Add/List/Delete Links)"
  echo "3) System Status & Config Overview"
  echo "4) List Active Whitelisted IPs"
  echo "5) Completely Uninstall"
  echo "6) Exit"
  echo "------------------------------------------------"
  read -p "Select an option [1-6]: " OPTION

  case $OPTION in
    1)
      install_spa
      ;;
    2)
      manage_users
      ;;
    3)
      show_status
      ;;
    4)
      list_ips
      ;;
    5)
      uninstall_spa
      ;;
    6)
      clear
      exit 0
      ;;
    *)
      echo -e "${RED}Invalid Option!${NC}"
      sleep 1
      ;;
  esac
done