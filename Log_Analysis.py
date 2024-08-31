import paramiko
import importlib
import json
import re
import logging
from subprocess import call
from dotenv import load_dotenv
import os
import sys

# Set up logging
logging.basicConfig(filename='compliance_check.log', 
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(filename)s - %(message)s')

def check_install_dependency(module_name):
    try:
        importlib.import_module(module_name)
    except ImportError:
        logging.info(f"{module_name} not found. Installing...")
        call(["pip", "install", module_name])

check_install_dependency("paramiko")


# Load environment variables from .env file
load_dotenv()

# Retrieve credentials from environment variables
hostname = os.getenv('SSH_HOSTNAME')
username = os.getenv('SSH_USERNAME')
password = os.getenv('SSH_PASSWORD')

def create_ssh_client(hostname, username, password):
    """
    Creates and returns an SSH client connected to the remote host using password authentication.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(hostname, username=username, password=password)
        logging.info("SSH connection established using password authentication.")
        return ssh
    except paramiko.AuthenticationException as e:
        logging.error(f"Authentication failed: {e}")
        raise
    except Exception as e:
        logging.error(f"Error establishing SSH connection: {e}")
        raise

def run_command(ssh, command):
    """
    Executes a command on the remote SSH client and returns the output.
    """
    stdin, stdout, stderr = ssh.exec_command(command)
    return stdout.read().decode()

def check_elk_installed(ssh):
    """
    Check if Elasticsearch, Logstash, and Kibana are installed on the remote server.
    """
    try:
        # Check if Elasticsearch is installed
        elastic_installed = run_command(ssh, "dpkg -l | grep elasticsearch")
        # Check if Logstash is installed
        logstash_installed = run_command(ssh, "dpkg -l | grep logstash")
        # Check if Kibana is installed
        kibana_installed = run_command(ssh, "dpkg -l | grep kibana")
        
        if elastic_installed and logstash_installed and kibana_installed:
            logging.info("ELK stack is installed.")
            return True
        else:
            logging.error("One or more ELK stack components are not installed.")
            return False
    except Exception as e:
        logging.error(f"Failed to check ELK stack installation: {e}")
        return False

def check_elk_running(ssh):
    """
    Check if Elasticsearch, Logstash, and Kibana are running on the remote server.
    """
    try:
        # Check if Elasticsearch is running
        elastic_status = run_command(ssh, "systemctl is-active elasticsearch").strip()
        # Check if Logstash is running
        logstash_status = run_command(ssh, "systemctl is-active logstash").strip()
        # Check if Kibana is running
        kibana_status = run_command(ssh, "systemctl is-active kibana").strip()
        
        if elastic_status == "active" and logstash_status == "active" and kibana_status == "active":
            logging.info("ELK stack is running.")
            return True
        else:
            logging.error("One or more ELK stack components are not running.")
            return False
    except Exception as e:
        logging.error(f"Failed to check ELK stack running status: {e}")
        return False

def check_log_analysis(ssh):
    try:
        # Example: Check syslog for recent security events
        syslog_content = run_command(ssh, 'sudo tail -n 50 /var/log/syslog')
        
        if 'Unauthorized access' in syslog_content:
            logging.info("Log analysis shows unauthorized access detected.")
            return {"log_analysis": "Unauthorized access detected"}
        else:
            logging.info("No unauthorized access detected.")
            return {"log_analysis": "No unauthorized access detected"}
        
    except paramiko.AuthenticationException:
        logging.error("Authentication failed. Please check your credentials.")
        return {"log_analysis": "Authentication failed"}
    except paramiko.SSHException as ssh_err:
        logging.error(f"SSH connection failed: {ssh_err}")
        return {"log_analysis": f"SSH connection failed: {ssh_err}"}

def check_compliance(ssh):
    """
    Connects to the server and performs various compliance checks.
    """
    compliance_issues = {}
    
    try:
        logging.info("Starting compliance checks.")
        
        if not check_elk_installed(ssh):
            compliance_issues['elk_installed'] = "ELK stack components are not installed."
        else:
            compliance_issues['elk_installed'] = "ELK stack components are installed."
            

        if not check_elk_running(ssh):
            compliance_issues['elk_running'] = "ELK stack components are not running."
        else:
            compliance_issues['elk_running'] = "ELK stack components are running."

        log_analysis_result = check_log_analysis(ssh)
        compliance_issues.update(log_analysis_result)
        
        # Add more compliance checks here as needed
        
        # Save compliance results to a JSON file
        with open('compliance_issues.json', 'w') as file:
            json.dump(compliance_issues, file, indent=4)
        
        logging.info("Compliance check completed.")
        return compliance_issues
    
    except Exception as e:
        logging.error(f"Error in check_compliance: {e}")
        return {"compliance_check": f"Error: {e}"}

if __name__ == "__main__":
    try:
        ssh = create_ssh_client(hostname, username, password)
        
        compliance_issues = check_compliance(ssh)
        print(json.dumps(compliance_issues, indent=4))
        
        ssh.close()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")
