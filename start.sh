#!/bin/bash
# setup_and_run_agent.sh

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a /var/log/flaskagent_setup.log
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

# Step 1: Create a dedicated user for the agent
log "Creating dedicated user..."
id -u flaskagent &>/dev/null || useradd -r -s /bin/false flaskagent
check_success "User creation"

# Step 2: Create a virtual environment
log "Creating virtual environment..."
python3 -m venv /opt/flaskagent_env
check_success "Virtual environment creation"

# Merging to use only iptables instead of nftables
log "Configuring iptables..."
update-alternatives --set iptables /usr/sbin/iptables-legacy
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
iptables -L
check_success "iptables configuration"

# Step 3: Install dependencies in the virtual environment
log "Installing dependencies..."
/opt/serveragnet_env/bin/pip install --no-cache-dir flask flask-socketio python-dotenv psutil
check_success "Dependency installation"

# Step 4: Copy agent script and other necessary files
log "Copying agent files..."
mkdir -p /opt/flaskagent
cp main.py /opt/flaskagent/
cp manage.py /opt/flaskagent/
cp .env /opt/flaskagent/
check_success "File copying"

# Step 5: Set proper permissions
log "Setting permissions..."
chown -R flaskagent:flaskagent /opt/flaskagent
chmod 750 /opt/flaskagent
chmod 640 /opt/flaskagent/.env
check_success "Permission setting"

# Step 6: Create a systemd service file
log "Creating systemd service..."
cat << EOF > /etc/systemd/system/flaskagent.service
[Unit]
Description=Flask Agent Service
After=network.target

[Service]
User=flaskagent
Group=flaskagent
WorkingDirectory=/opt/flaskagent
ExecStart=/opt/flaskagent_env/bin/python /opt/flaskagent/agent.py
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=flaskagent

[Install]
WantedBy=multi-user.target
EOF
check_success "Systemd service creation"

# Step 7: Create a sudoers file for the agent
log "Configuring sudoers..."
echo "flaskagent ALL=(ALL) NOPASSWD: /sbin/iptables" > /etc/sudoers.d/flaskagent
chmod 0440 /etc/sudoers.d/flaskagent
check_success "Sudoers configuration"

# Step 8: Reload systemd and start the service
log "Starting Flask Agent service..."
systemctl daemon-reload
systemctl start flaskagent
systemctl enable flaskagent
check_success "Service start"

# Step 9: Set up log rotation
log "Setting up log rotation..."
cat << EOF > /etc/logrotate.d/flaskagent
/var/log/flaskagent.log {
    weekly
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 flaskagent flaskagent
}
EOF
check_success "Log rotation setup"

# Step 10: Set up basic firewall rules
log "Setting up firewall rules..."
iptables-save > /etc/iptables/rules.v4
check_success "Firewall configuration"

log "Flask Agent setup complete and service started."
log "Please review the setup log at /var/log/flaskagent_setup.log for any issues."