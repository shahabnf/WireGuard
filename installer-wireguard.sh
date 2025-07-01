#!/bin/bash

# Ensure the script is run with sudo or as root
if [[ "$EUID" -ne 0 ]]; then
  echo "❌ This script must be run as root. Please use sudo:"
  echo "   sudo $0"
  exit 1
fi

WG_INTERFACE="wg0"
WG_DIR="/etc/wireguard"
CLIENT_DIR=/wireguard/clients
SERVER_PRIVATE_KEY="$WG_DIR/server_private.key"
SERVER_PUBLIC_KEY="$WG_DIR/server_public.key"

# Detect external interface
EXT_IF=$(ip route get 1 | grep -oP 'dev \K\S+')

echo "🔧 Installing WireGuard and dependencies..."
sudo apt update && sudo apt install -y wireguard qrencode iptables

echo "🔐 Generating server keys..."
umask 077
sudo wg genkey | sudo tee $SERVER_PRIVATE_KEY | wg pubkey | sudo tee $SERVER_PUBLIC_KEY > /dev/null

SERVER_PRIV=$(sudo cat $SERVER_PRIVATE_KEY)
SERVER_PUB=$(sudo cat $SERVER_PUBLIC_KEY)

# Prompt for server public IP or domain
read -p "🌐 Enter your server's public IP or domain: " SERVER_ENDPOINT_IP

# Prompt the user to enter a custom WireGuard port.
# Accept only ports between 1024 and 65535. Use 51820 if left blank.
while true; do
  read -p "🔢 Enter WireGuard listen port [Press Enter for default: 51820]: " WireGuard_PORT
  WireGuard_PORT=${WireGuard_PORT:-51820}
  if [[ "$WireGuard_PORT" =~ ^[0-9]+$ ]] && [ "$WireGuard_PORT" -ge 1024 ] && [ "$WireGuard_PORT" -le 65535 ]; then
    break
  else
    echo "❌ Invalid port. Please enter a number between 1024 and 65535."
  fi
done

echo "📄 Creating WireGuard server config..."
sudo bash -c "cat > $WG_DIR/$WG_INTERFACE.conf" <<EOF
[Interface]
Address = 10.10.10.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXT_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXT_IF -j MASQUERADE
EOF

echo "🔓 Enabling IP forwarding..."
sudo sed -i '/^#net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
sudo sed -i '/^net.ipv4.ip_forward/ s/=.*/=1/' /etc/sysctl.conf
sudo sysctl -p

echo "🔥 Configuring UFW firewall rules..."
sudo ufw allow 51820/udp

echo "🚀 Starting and enabling WireGuard..."
sudo systemctl enable wg-quick@$WG_INTERFACE
sudo systemctl start wg-quick@$WG_INTERFACE

echo "✅ WireGuard is installed and running."

# Save server public key and endpoint to a config file for client manager
mkdir -p "$CLIENT_DIR"
cat <<EOF > "$CLIENT_DIR/.server.conf"
SERVER_PUBLIC_KEY=$SERVER_PUB
SERVER_ENDPOINT=$SERVER_ENDPOINT_IP:$WireGuard_PORT
EOF

# Download or link the client manager script here
MANAGER_SCRIPT="$CLIENT_DIR/wireguard-manager.sh"

echo "📦 Creating WireGuard client manager..."
cat > "$MANAGER_SCRIPT" <<'EOM'
#!/bin/bash

# Ensure the script is run with sudo or as root
if [[ "$EUID" -ne 0 ]]; then
  echo "❌ This script must be run as root. Please use sudo:"
  echo "   sudo $0"
  exit 1
fi

WG_DIR=/wireguard/clients
WG_CONF="/etc/wireguard/wg0.conf"
START_IP=2 # Start assigning IPs from .2

source "$WG_DIR/.server.conf"

mkdir -p "$WG_DIR"

function add_user() {
  read -p "Enter new client name: " client
  if [ -f "$WG_DIR/${client}.conf" ]; then
    echo "❌ Client '$client' already exists."
    return
  fi

  wg genkey | tee "$WG_DIR/${client}_private.key" | wg pubkey > "$WG_DIR/${client}_public.key"

  # Safely get the highest used IP in wg0.conf and increment it
  last_ip=$(grep -oP '10\.10\.10\.\K[0-9]+' "$WG_CONF" | sort -n | tail -n 1)
  if [[ -z "$last_ip" ]]; then
    ip=2
  else
    ip=$((last_ip + 1))
  fi
  client_ip="10.10.10.$ip"

  echo -e "\n[Peer]
PublicKey = $(cat "$WG_DIR/${client}_public.key")
AllowedIPs = $client_ip/32" | sudo tee -a "$WG_CONF" > /dev/null

  echo "[Interface]
PrivateKey = $(cat "$WG_DIR/${client}_private.key")
Address = $client_ip/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_ENDPOINT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25" > "$WG_DIR/${client}.conf"

  echo "✅ Client '$client' created with IP $client_ip"
  echo "📄 You can access the config file at: $WG_DIR/${client}.conf"
  echo "🔄 Restarting WireGuard to apply changes..."
  sudo systemctl restart wg-quick@wg0
}

function list_users() {
  echo "📋 Existing WireGuard clients:"
  ls "$WG_DIR" | grep '.conf' | sed 's/\.conf$//'
}

function show_qr() {
  read -p "Enter client name to show QR: " client
  conf_file="$WG_DIR/${client}.conf"
  if [ -f "$conf_file" ]; then
    echo "📱 QR code for '$client':"
    qrencode -t ansiutf8 < "$conf_file"
  else
    echo "❌ No config found for client '$client'."
  fi
}

function show_status() {
  echo "📡 WireGuard status (sudo wg):"
  sudo wg
}

function menu() {
  while true; do
    echo ""
    echo "========= WireGuard Manager ========="
    echo "1) Add new client"
    echo "2) List existing clients"
    echo "3) Generate QR code for a client"
    echo "4) Show WireGuard status"
    echo "5) Exit"
    echo "====================================="
    read -p "Choose an option [1-5]: " choice
    case $choice in
      1) add_user ;;
      2) list_users ;;
      3) show_qr ;;
      4) show_status ;;
      5) exit ;;
      *) echo "❌ Invalid choice." ;;
    esac
  done
}

menu
EOM

chmod +x "$MANAGER_SCRIPT"

echo ""
echo "✅ All done. You can now run the client manager with:"
echo "   $MANAGER_SCRIPT"