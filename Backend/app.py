from flask import Flask, request, jsonify
import os
import importlib.util
import paramiko
from flask_cors import CORS
import logging

app = Flask(__name__)

# Configure logging to include filename and line number
logging.basicConfig(
    level=logging.INFO,
    filename='LogFile.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - File: %(filename)s, Line: %(lineno)d - %(message)s'
)

# Allow all origins
CORS(app)

def create_ssh_connection(hostname, username, password):
    """Create and return an SSH connection."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, password=password)
        print(f"{logging.getLevelName(logging.INFO)} - File: {__file__}, Line: {22} - SSH connection established successfully.")
        logging.info("SSH connection established successfully.")
    except paramiko.SSHException as e:
        print(f"{logging.getLevelName(logging.ERROR)} - File: {__file__}, Line: {26} - SSH connection error: {e}")
        logging.error(f"SSH connection error: {e}")
        raise
    return ssh

@app.route('/api/scripts', methods=['GET'])
def list_scripts():
    checks_dir = "Checks"  # Path to your Checks folder
    scripts = [f for f in os.listdir(checks_dir) if f.endswith('.py')]
    print(f"{logging.getLevelName(logging.INFO)} - File: {__file__}, Line: {34} - Listing scripts: {scripts}")
    logging.info(f"Listing scripts: {scripts}")
    return jsonify(scripts)

def run_check_script(script_name):
    script_path = os.path.join('Checks', script_name)
    if not os.path.exists(script_path):
        print(f"{logging.getLevelName(logging.ERROR)} - File: {__file__}, Line: {43} - Script not found: {script_name}")
        return {"error": "Script not found"}, 404

    spec = importlib.util.spec_from_file_location("module.name", script_path)
    module = importlib.util.module_from_spec(spec)
    
    try:
        spec.loader.exec_module(module)

        # Retrieve SSH credentials from environment variables
        hostname = os.getenv('SSH_HOSTNAME')
        username = os.getenv('SSH_USERNAME')
        password = os.getenv('SSH_PASSWORD')

        ssh = create_ssh_connection(hostname, username, password)

        # Call the run_checks method with the ssh connection
        print(f"{logging.getLevelName(logging.INFO)} - File: {__file__}, Line: {61} - Running checks using script: {script_name}")
        logging.info(f"Running checks using script: {script_name}")
        return module.run_checks(ssh, password)  # Pass the ssh connection and password here
        
    except Exception as e:
        print(f"{logging.getLevelName(logging.ERROR)} - File: {__file__}, Line: {66} - Error executing script: {e}")
        return {"error": str(e)}, 500

@app.route('/store_credentials', methods=['POST'])
def store_credentials():
    data = request.json
    hostname = data.get('hostname')
    username = data.get('username')
    password = data.get('password')

    # Store credentials as environment variables
    os.environ['SSH_HOSTNAME'] = hostname
    os.environ['SSH_USERNAME'] = username
    os.environ['SSH_PASSWORD'] = password

    print(f"{logging.getLevelName(logging.INFO)} - File: {__file__}, Line: {80} - Credentials stored successfully.")
    logging.info("Credentials stored successfully.")
    return jsonify(success=True)

@app.route('/run_check', methods=['POST'])
def run_check():
    data = request.json
    script_name = data.get('script_name')
    print(f"{logging.getLevelName(logging.INFO)} - File: {__file__}, Line: {88} - Request to run check script: {script_name}")
    logging.info(f"Request to run check script: {script_name}")
    result = run_check_script(script_name)
    return jsonify(result)

@app.route('/create_package', methods=['POST'])
def create_package():
    package_data = request.json
    # Save package configuration to database (placeholder)
    print(f"{logging.getLevelName(logging.INFO)} - File: {__file__}, Line: {99} - Package created with data: {package_data}")
    logging.info(f"Package created with data: {package_data}")
    return jsonify(success=True)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    app.run(port=5000, debug=True)
