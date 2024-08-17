import importlib
import json
import re
import paramiko
import logging
from subprocess import call

# Set up logging
logging.basicConfig(filename='compliance_check.log', 
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def check_install_dependency(module_name):
    try:
        importlib.import_module(module_name)
    except ImportError:
        logging.info(f"{module_name} not found. Installing...")
        call(["pip", "install", module_name])

check_install_dependency("paramiko")

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

def run_command(ssh_client, command):
    """
    Executes a command on the remote SSH client and returns the output.
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    return stdout.read().decode()

def track_and_monitor_access(ssh):
    """
    Connects to a remote Linux machine via SSH and retrieves and verifies log information.
    """
    issues = []
    try:
        logging.info("SSH connection established for track and monitor access check.")
        
        logs = run_command(ssh, "cat /var/log/auth.log")
        if not re.search(r'USER_LOGIN', logs):
            issues.append("Audit trails not present in /var/log/auth.log.")
        
        time_sync = run_command(ssh, "timedatectl")
        if not re.search(r'Synchronized', time_sync):
            issues.append("System clocks are not synchronized.")
        
        return issues
    
    except Exception as e:
        logging.error(f"Error in track_and_monitor_access: {e}")
        return [f"Error: {e}"]

def test_security_systems(ssh):
    """
    Connects to a remote Linux machine via SSH and performs security system tests.
    """
    issues = []
    try:
        ids_ips_status = run_command(ssh, "systemctl status snort")
        if not re.search(r'active \(running\)', ids_ips_status):
            issues.append("IDS/IPS (snort) is not running or not active.")
        
        return issues
    
    except Exception as e:
        logging.error(f"Error in test_security_systems: {e}")
        return [f"Error: {e}"]
    
def check_default_passwords(ssh):
    """
    Connects to a remote Linux machine and checks for default passwords and configurations.
    """
    issues = []
    try:
        logging.info("SSH connection established for default passwords check.")
        
        # Check SSH configuration
        ssh_config = run_command(ssh, "grep 'PasswordAuthentication' /etc/ssh/sshd_config")
        if re.search(r'PasswordAuthentication\s+yes', ssh_config):
            issues.append("PasswordAuthentication is enabled in SSH configuration. Consider disabling it.")
        
        # Check for default MySQL accounts
        mysql_users = run_command(ssh, "mysql -e 'SELECT user FROM mysql.user;'")
        default_mysql_users = re.findall(r'root|admin', mysql_users, re.IGNORECASE)
        if default_mysql_users:
            issues.append(f"Default MySQL users found: {', '.join(default_mysql_users)}")
        
        # Check for default PostgreSQL accounts
        postgres_users = run_command(ssh, "sudo -u postgres psql -c \"\\du\"")
        default_postgres_users = re.findall(r'postgres|admin', postgres_users, re.IGNORECASE)
        if default_postgres_users:
            issues.append(f"Default PostgreSQL users found: {', '.join(default_postgres_users)}")
        
        # Check for default web application accounts (example for WordPress)
        # Make sure to adjust the path and method according to the actual web application
        wp_config = run_command(ssh, "grep 'define(' /var/www/html/wp-config.php")
        if re.search(r'admin', wp_config, re.IGNORECASE):
            issues.append("Default admin accounts found in WordPress configuration.")
        
        return issues
    
    except Exception as e:
        logging.error(f"Error in check_default_passwords: {e}")
        return [f"Error: {e}"]

def check_security_policy(ssh):
    """
    Connects to a remote Linux machine via SSH and verifies the information security policy.
    """
    issues = []
    try:
        logging.info("SSH connection established for security policy check.")
        
        policies = run_command(ssh, "ls /etc/security/policies")
        if not re.search(r'policy_document.txt', policies):
            issues.append("Security policy document (policy_document.txt) is missing or outdated.")
        
        awareness_program = run_command(ssh, "cat /etc/security/awareness_program_status")
        if not re.search(r'active', awareness_program):
            issues.append("Security awareness program is not active.")
        
        return issues
    
    except Exception as e:
        logging.error(f"Error in check_security_policy: {e}")
        return [f"Error: {e}"]

def get_firewall_rules(ssh):
    """
    Connects to a remote Linux machine and retrieves detailed firewall rules using iptables.
    """
    issues = []
    try:
        logging.info("SSH connection established to retrieve firewall rules.")
        
        # Retrieve all iptables rules in a detailed format
        rules = run_command(ssh, "iptables -L -n -v --line-numbers")
        
        # Retrieve NAT table rules
        nat_rules = run_command(ssh, "iptables -t nat -L -n -v --line-numbers")
        
        # Retrieve mangle table rules
        mangle_rules = run_command(ssh, "iptables -t mangle -L -n -v --line-numbers")
        
        # Retrieve raw table rules
        raw_rules = run_command(ssh, "iptables -t raw -L -n -v --line-numbers")

        # Collect all rules
        all_rules = {
            'filter_rules': rules,
            'nat_rules': nat_rules,
            'mangle_rules': mangle_rules,
            'raw_rules': raw_rules
        }
        
        # Example issue checks (you can expand these as needed)
        if not re.search(r'CHAIN\s+INPUT\s+ACCEPT', rules):
            issues.append("Firewall should default to deny all inbound traffic.")
        if not re.search(r'CHAIN\s+OUTPUT\s+ACCEPT', rules):
            issues.append("Firewall should default to deny all outbound traffic.")
        
        # You can add additional checks for specific rules or ports here
        
        return all_rules, issues
    
    except Exception as e:
        logging.error(f"Error in get_firewall_rules: {e}")
        return None, [f"Error: {e}"]


def analyze_firewall_rules(all_rules):
    """
    Analyzes detailed firewall rules to determine compliance status.
    """
    issues = []
    compliance_status = 'unknown'
    
    if all_rules is None:
        issues.append("Firewall rules could not be retrieved.")
        compliance_status = 'non-compliant'
        return compliance_status, issues
    
    filter_rules = all_rules.get('filter_rules', '')
    nat_rules = all_rules.get('nat_rules', '')
    mangle_rules = all_rules.get('mangle_rules', '')
    raw_rules = all_rules.get('raw_rules', '')

    # Check for specific port rules
    if 'ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22' in filter_rules:
        compliance_status = 'compliant'
    else:
        issues.append("No rule found allowing SSH (port 22).")
        compliance_status = 'non-compliant'

    # Additional detailed checks can be added here

    return compliance_status, issues


def check_encryption(hostname, username, password):
    """
    Connects to a remote Linux machine via SSH and checks for encryption of data.
    """
    issues = []
    try:
        ssh = create_ssh_client(hostname, username, password)
        logging.info("SSH connection established for encryption check.")
        
        encryption_status = run_command(ssh, "lsblk -f")
        if not re.search(r'crypto_LUKS', encryption_status):
            issues.append("Data at rest is not encrypted using LUKS or other encryption methods.")
        
        https_status = run_command(ssh, "grep 'listen 443' /etc/nginx/sites-enabled/default")
        if not re.search(r'listen\s+443', https_status):
            issues.append("HTTPS is not enabled for data in transit.")
        
        ssh.close()
        return issues
    
    except Exception as e:
        logging.error(f"Error in check_encryption: {e}")
        return [f"Error: {e}"]

def check_network_monitoring(hostname, username, password):
    """
    Connects to a remote Linux machine and checks for network monitoring tools.
    """
    issues = []
    try:
        ssh = create_ssh_client(hostname, username, password)
        logging.info("SSH connection established for network monitoring check.")
        
        monitoring_tools = run_command(ssh, r"dpkg -l | grep 'ntopng\|wireshark\|tcpdump'")
        if not re.search(r'ntopng|wireshark|tcpdump', monitoring_tools):
            issues.append("Network monitoring tools are not installed or active.")
        
        unusual_activity = run_command(ssh, "netstat -an")
        if re.search(r'ESTABLISHED\s+.*:22', unusual_activity):
            issues.append("Unusual network activity detected on port 22.")
        
        ssh.close()
        return issues
    
    except Exception as e:
        logging.error(f"Error in check_network_monitoring: {e}")
        return [f"Error: {e}"]

def check_compliance(hostname, username, password):
    """
    Connects to the VM, retrieves firewall rules, and checks for compliance including default passwords.
    """
    compliance_issues = {}
    
    try:
        ssh = create_ssh_client(hostname, username, password)
        
        issues = track_and_monitor_access(ssh)
        if issues:
            compliance_issues['track_and_monitor_access'] = issues
        
        issues = test_security_systems(ssh)
        if issues:
            compliance_issues['test_security_systems'] = issues
        
        issues = check_security_policy(ssh)
        if issues:
            compliance_issues['check_security_policy'] = issues
        
        firewall_rules, issues = get_firewall_rules(ssh)
        if issues:
            compliance_issues['get_firewall_rules'] = issues
        compliance_status, issues = analyze_firewall_rules(firewall_rules)
        if issues:
            compliance_issues['analyze_firewall_rules'] = issues
        
        issues = check_default_passwords(ssh)
        if issues:
            compliance_issues['check_default_passwords'] = issues
        
        issues = check_encryption(hostname, username, password)
        if issues:
            compliance_issues['check_encryption'] = issues
        
        issues = check_network_monitoring(hostname, username, password)
        if issues:
            compliance_issues['check_network_monitoring'] = issues
        
        # Save compliance results to a JSON file
        with open('compliance_issues.json', 'w') as file:
            json.dump(compliance_issues, file, indent=4)
        
        logging.info("Compliance check completed.")
        return compliance_issues
    
    except Exception as e:
        logging.error(f"Error in check_compliance: {e}")
        return [f"Error: {e}"]

if __name__ == "__main__":
    # Host details
    hostname = "20.244.90.235"
    username = "ansh"
    password = "MinorProject@123"
    try:
        ssh = create_ssh_client(hostname, username, password)
        
        check_compliance(hostname=hostname, username=username, password=password)
        
        ssh.close()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
