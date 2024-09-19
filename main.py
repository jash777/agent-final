# agent.py

from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from manage import IPTablesManager, SystemManager, ApplicationManager
import logging
from functools import wraps
import json
import os
from dotenv import load_dotenv
import subprocess

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
socketio = SocketIO(app, cors_allowed_origins=os.getenv('CORS_ORIGINS', '*').split(','))

logging.basicConfig(filename=os.getenv('LOG_FILE', 'agent.log'), 
                    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != os.getenv('API_KEY'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def execute_iptables_command(command):
    try:
        subprocess.run(['iptables', '-w', '10'] + command, check=True)
        logger.info(f"Executed iptables command: {' '.join(command)}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing iptables command: {e}")
        return False

def get_chain_policy(chain):
    try:
        result = subprocess.run(['iptables', '-S', chain], capture_output=True, text=True, check=True)
        policy_line = result.stdout.split('\n')[0]
        return policy_line.split()[2]
    except subprocess.CalledProcessError as e:
        logger.error(f"Error getting policy for chain {chain}: {e}")
        return None

def set_chain_policy(chain, policy):
    return execute_iptables_command(['-P', chain, policy])

def get_existing_rules():
    try:
        result = subprocess.run(['iptables-save'], capture_output=True, text=True, check=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        logger.error(f"Error getting existing iptables rules: {e}")
        return []

def rule_exists(rule, existing_rules):
    return any(line.strip() == f"-A {' '.join(rule)}" for line in existing_rules)

def add_rule_if_not_exists(rule, existing_rules):
    if not rule_exists(rule, existing_rules):
        return execute_iptables_command(['-A'] + rule)
    else:
        logger.info(f"Rule already exists, skipping: {' '.join(rule)}")
        return True

def initialize_agent():
    logger.info("Initializing agent and setting up iptables rules...")

    existing_rules = get_existing_rules()

    # Define essential rules
    essential_rules = [
        ['INPUT', '-i', 'lo', '-j', 'ACCEPT'],
        ['OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
        ['INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
        ['INPUT', '-p', 'tcp', '--dport', '5000', '-j', 'ACCEPT'],
        ['OUTPUT', '-p', 'tcp', '--dport', '5000', '-j', 'ACCEPT'],
        ['INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
        ['OUTPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
        ['OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'],
        ['OUTPUT', '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'],
        ['OUTPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
        ['OUTPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'],
        ['OUTPUT', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'],
        ['INPUT', '-p', 'icmp', '--icmp-type', 'echo-request', '-j', 'ACCEPT'],
        ['OUTPUT', '-p', 'icmp', '--icmp-type', 'echo-reply', '-j', 'ACCEPT']
    ]

    # Set default policies to DROP if not already set
    for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
        current_policy = get_chain_policy(chain)
        if current_policy != 'DROP':
            set_chain_policy(chain, 'DROP')

    # Add essential rules if they don't exist
    for rule in essential_rules:
        add_rule_if_not_exists(rule, existing_rules)

    logger.info("Agent initialized and iptables rules set up efficiently.")

@app.route('/')
def agent_status():
    return jsonify({"status": "Agent is running"})

@app.route('/apply-rules', methods=['POST'])
@require_api_key
def apply_rules():
    rules = request.json.get('rules', [])
    results = []
    for rule in rules:
        if rule.get('direction') == 'inbound':
            success = IPTablesManager.inbound_rule(rule)
        elif rule.get('direction') == 'outbound':
            success = IPTablesManager.outbound_rule(rule)
        else:
            success = False
        results.append({'rule': rule, 'success': success})
    return jsonify({'status': 'completed', 'results': results})

@app.route('/iptables_rules', methods=['GET'])
@require_api_key
def get_iptables_rules_route():
    try:
        rules = IPTablesManager.get_rules()
        return jsonify({'status': 'success', 'rules': rules})
    except Exception as e:
        logger.error(f"Error retrieving iptables rules: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/processes', methods=['GET'])
@require_api_key
def get_processes():
    return jsonify(SystemManager.get_running_processes())

@app.route('/users', methods=['GET', 'POST', 'DELETE'])
@require_api_key
def manage_users():
    if request.method == 'GET':
        return jsonify({'users': SystemManager.get_non_default_users()})
    elif request.method == 'POST':
        data = request.json
        success, message = SystemManager.add_user(data['username'], data['password'], data.get('groups', []))
        return jsonify({'message': message}), 200 if success else 400
    elif request.method == 'DELETE':
        success, message = SystemManager.remove_user(request.json['username'])
        return jsonify({'message': message}), 200 if success else 400

@app.route('/applications', methods=['GET'])
@require_api_key
def get_applications():
    try:
        applications = ApplicationManager.get_installed_applications()
        return jsonify({
            'status': 'success',
            'count': len(applications),
            'applications': applications
        })
    except Exception as e:
        logger.error(f"Error in get_applications route: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def send_process_data():
    while True:
        socketio.emit('process_data', json.dumps(SystemManager.get_running_processes()))
        socketio.sleep(int(os.getenv('PROCESS_UPDATE_INTERVAL', 60)))

@socketio.on('connect')
def handle_connect():
    socketio.start_background_task(send_process_data)

if __name__ == "__main__":
    initialize_agent()
    socketio.run(app, 
                 host=os.getenv('HOST', '0.0.0.0'), 
                 port=int(os.getenv('PORT', 5000)), 
                 debug=os.getenv('DEBUG', 'False').lower() == 'true')