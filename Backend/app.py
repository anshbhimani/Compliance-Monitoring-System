from flask import Flask, request, jsonify
import os
import importlib.util
import paramiko
from flask_cors import CORS
import logging

app = Flask(__name__)

hostname = ''
username = ''
password = ''

SCRIPTS_DIR = '../Backend/scripts'
# Mock database for compliance groups
compliance_groups = []


# Configure logging to include filename and line number
logging.basicConfig(
    level=logging.INFO,
    filename='LogFile.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - File: %(filename)s, Line: %(lineno)d - %(message)s'
)


# Allow all origins
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

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

@app.route('/api/scripts', methods=['GET', 'POST'])
def manage_scripts():
    if request.method == 'GET':
        scripts = [f for f in os.listdir(SCRIPTS_DIR) if f.endswith('.py')]
        return jsonify(scripts)

    if request.method == 'POST':
        script_name = request.form.get('scriptName')
        file = request.files.get('file')

        if not script_name or not file:
            return jsonify({"error": "Script name and file are required"}), 400

        file_path = os.path.join(SCRIPTS_DIR, f"{script_name}.py")

        if os.path.exists(file_path):
            return jsonify({"error": "Script with this name already exists"}), 400

        # Save the new script
        file.save(file_path)
        return jsonify({"success": True, "message": "Script uploaded successfully"}), 201

def run_check_script(script_name):
    script_path = os.path.join('scripts', script_name)
    if not os.path.exists(script_path):
        print(f"{logging.getLevelName(logging.ERROR)} - File: {__file__}, Line: {43} - Script not found: {script_name}")
        return {"error": "Script not found"}, 404

    spec = importlib.util.spec_from_file_location("module.name", script_path)
    module = importlib.util.module_from_spec(spec)
    
    try:
        spec.loader.exec_module(module)

        # Retrieve SSH credentials from environment variables
        # hostname = os.getenv('SSH_HOSTNAME')
        # username = os.getenv('SSH_USERNAME')
        # password = os.getenv('SSH_PASSWORD')

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

@app.route('/api/scripts/<script_name>', methods=['POST'])
def run_check(script_name):
    print(f"{logging.getLevelName(logging.INFO)} - File: {__file__}, Line: {88} - Request to run check script: {script_name}")
    logging.info(f"Request to run check script: {script_name}")
    print(f"Request to run check script: {script_name}")
    result = run_check_script(script_name)
    print(f"Result is \n {result}")
    return jsonify(result)

@app.route('/create_package', methods=['POST'])
def create_package():
    package_data = request.json
    # Save package configuration to database (placeholder)
    print(f"{logging.getLevelName(logging.INFO)} - File: {__file__}, Line: {99} - Package created with data: {package_data}")
    logging.info(f"Package created with data: {package_data}")
    return jsonify(success=True)

@app.route('/api/scripts/<script_id>', methods=['DELETE'])
def delete_script(script_id):
    global scripts_db
    scripts_db = [script for script in scripts_db if script['id'] != script_id]
    logging.info(f"Script deleted: {script_id}")
    return jsonify(success=True)

@app.route('/api/compliance-groups', methods=['GET', 'POST'])
def manage_compliance_groups():
    if request.method == 'GET':
        return jsonify(compliance_groups)
    
    if request.method == 'POST':
        group_data = request.json
        if not group_data.get('name') or not group_data.get('scripts'):
            return jsonify({"error": "Group name and scripts are required"}), 400

        compliance_groups.append(group_data)
        return jsonify(group_data), 201
    
@app.route('/load-data', methods=['GET'])
def load_data():
    # Placeholder function for providing load data for the chart
    # In a real scenario, you would retrieve this data from your monitoring or logging system
    load_data_response = {
        "timestamps": ["2024-11-01", "2024-11-02", "2024-11-03"],
        "loads": [10, 20, 30]
    }
    return jsonify(load_data_response)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    app.run(port=5000, debug=True)
