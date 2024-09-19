#!/bin/bash
# setup_and_run_agent.sh

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a /var/log/serveragent_setup.log
}

# Function to check if a command succeeded
check_success() {
    if [ $? -eq 0 ]; then
        log "Success: $1"
    else
        log "Error: $1 failed"
        exit 1
    fi
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   log "This script must be run as root"
    exit 1
fi

log "Starting Flask Agent setup..."

# Step 1: Install Git
log "Installing Git..."
apt-get update
apt-get install -y git
check_success "Git installation"

# Step 2: Clone the repository
log "Cloning the repository..."
git clone https://github.com/jash777/agent-final.git /opt/serveragent
check_success "Repository cloning"

# Step 3: Create a dedicated user for the agent
log "Creating dedicated user..."
id -u serveragent &>/dev/null || useradd -r -s /bin/false serveragent
check_success "User creation"

# Step 4: Create a virtual environment
log "Creating virtual environment..."
python3 -m venv /opt/serveragent_env
check_success "Virtual environment creation"

# Merging to use only iptables instead of nftables
log "Configuring iptables..."
update-alternatives --set iptables /usr/sbin/iptables-legacy
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
iptables -L
check_success "iptables configuration"

# Step 5: Install dependencies in the virtual environment
log "Installing dependencies..."
/opt/serveragent_env/bin/pip install --no-cache-dir -r /opt/serveragent/requirements.txt
check_success "Dependency installation"

# Step 6: Set proper permissions
log "Setting permissions..."
chown -R serveragent:serveragent /opt/serveragent
chmod 750 /opt/serveragent
chmod 640 /opt/serveragent/.env
check_success "Permission setting"

# Step 7: Create a systemd service file
log "Creating systemd service..."
cat << EOF > /etc/systemd/system/serveragent.service
[Unit]
Description=Flask Agent Service
After=network.target

[Service]
User=serveragent
Group=serveragent
WorkingDirectory=/opt/serveragent
ExecStart=/opt/serveragent_env/bin/python /opt/serveragent/main.py
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=serveragent

[Install]
WantedBy=multi-user.target
EOF
check_success "Systemd service creation"

# Step 8: Create a sudoers file for the agent
log "Configuring sudoers..."
echo "serveragent ALL=(ALL) NOPASSWD: /sbin/iptables" > /etc/sudoers.d/serveragent
chmod 0440 /etc/sudoers.d/serveragent
check_success "Sudoers configuration"

# Step 9: Reload systemd and start the service
log "Starting Flask Agent service..."
systemctl daemon-reload
systemctl start serveragent
systemctl enable serveragent
check_success "Service start"

# Step 10: Set up log rotation
log "Setting up log rotation..."
cat << EOF > /etc/logrotate.d/serveragent
/var/log/serveragent.log {
    weekly
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 serveragent serveragent
}
EOF
check_success "Log rotation setup"

# Step 11: Set up basic firewall rules
log "Setting up firewall rules..."
iptables-save > /etc/iptables/rules.v4
check_success "Firewall configuration"

log "Flask Agent setup complete and service started."
log "Please review the setup log at /var/log/serveragent_setup.log for any issues."
