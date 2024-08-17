from subprocess import call
import importlib
import json
import re
import paramiko

def check_install_dependency(module_name):
    try:
        importlib.import_module(module_name)
    except ImportError:
        print(f"{module_name} not found. Installing...")
        call(["pip", "install", module_name])

check_install_dependency("paramiko")

def create_ssh_client(hostname, username, password):
    """
    Creates and returns an SSH client connected to the remote host.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    return ssh

def run_command(ssh_client, command):
    """
    Executes a command on the remote SSH client and returns the output.
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    return stdout.read().decode()

def track_and_monitor_access(hostname, username, password):
    """
    Connects to a remote Linux machine via SSH and retrieves and verifies log information.
    """
    issues = []
    try:
        ssh = create_ssh_client(hostname, username, password)
        print("Connection Successful!")
        
        logs = run_command(ssh, "cat /var/log/auth.log")
        if not re.search(r'USER_LOGIN', logs):
            issues.append("Audit trails not present in /var/log/auth.log.")
        
        time_sync = run_command(ssh, "timedatectl")
        if not re.search(r'Synchronized', time_sync):
            issues.append("System clocks are not synchronized.")
        
        ssh.close()
        return issues
    
    except Exception as e:
        return [f"Error: {e}"]

def test_security_systems(hostname, username, password):
    """
    Connects to a remote Linux machine via SSH and performs security system tests.
    """
    issues = []
    try:
        ssh = create_ssh_client(hostname, username, password)
        print("Connection Successful!")
        
        open_ports = run_command(ssh, "netstat -tuln")
        
        ids_ips_status = run_command(ssh, "systemctl status snort")
        if not re.search(r'active \(running\)', ids_ips_status):
            issues.append("IDS/IPS (snort) is not running or not active.")
        
        ssh.close()
        return issues
    
    except Exception as e:
        return [f"Error: {e}"]

def check_security_policy(hostname, username, password):
    """
    Connects to a remote Linux machine via SSH and verifies the information security policy.
    """
    issues = []
    try:
        ssh = create_ssh_client(hostname, username, password)
        print("Connection Successful!")
        
        policies = run_command(ssh, "ls /etc/security/policies")
        if not re.search(r'policy_document.txt', policies):
            issues.append("Security policy document (policy_document.txt) is missing or outdated.")
        
        awareness_program = run_command(ssh, "cat /etc/security/awareness_program_status")
        if not re.search(r'active', awareness_program):
            issues.append("Security awareness program is not active.")
        
        ssh.close()
        return issues
    
    except Exception as e:
        return [f"Error: {e}"]

def get_firewall_rules(hostname, username, password):
    """
    Connects to a remote Linux machine and retrieves firewall rules using iptables.
    """
    issues = []
    try:
        ssh = create_ssh_client(hostname, username, password)
        print("Connection Successful!")
        
        rules = run_command(ssh, "iptables -L -n -v")
        
        if not re.search(r'CHAIN\s+INPUT\s+ACCEPT', rules):
            issues.append("Firewall should default to deny all inbound traffic.")
        if not re.search(r'CHAIN\s+OUTPUT\s+ACCEPT', rules):
            issues.append("Firewall should default to deny all outbound traffic.")

        if re.search(r'ACCEPT\s+all\s+--\s+0.0.0.0/0\s+0.0.0.0/0', rules):
            issues.append("Firewall rules should restrict traffic to specific IP addresses and ports.")

        if not re.search(r'ACCEPT\s+tcp\s+--\s+0.0.0.0/0\s+0.0.0.0/0\s+tcp\s+dpt:443', rules):
            issues.append("Ensure HTTPS (port 443) is allowed for cardholder data transmission.")
        
        ssh.close()
        return rules, issues
    
    except Exception as e:
        return None, [f"Error: {e}"]

def check_default_passwords():
    """Check for default passwords in system configurations."""
    issues = []
    try:
        with open('/etc/passwd', 'r') as file:
            contents = file.read()
            default_accounts = ["root", "admin", "guest", "user"]
            for account in default_accounts:
                if re.search(f'{account}:', contents):
                    issues.append(f"Default account '{account}' found. Please change or disable.")
    except Exception as e:
        issues.append(f"Error: {e}")
    
    return issues

def analyze_firewall_rules(rules):
    """
    Analyzes firewall rules to determine compliance status.
    """
    issues = []
    compliance_status = 'unknown'
    
    if rules is None:
        issues.append("Firewall rules could not be retrieved.")
        compliance_status = 'non-compliant'
        return compliance_status, issues
    
    if 'ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22' in rules:
        compliance_status = 'compliant'
    else:
        issues.append("No rule found allowing SSH (port 22).")
        compliance_status = 'non-compliant'
    
    return compliance_status, issues

def check_encryption(hostname, username, password):
    """
    Connects to a remote Linux machine via SSH and checks for encryption of data.
    """
    issues = []
    try:
        ssh = create_ssh_client(hostname, username, password)
        print("Connection Successful!")
        
        encryption_status = run_command(ssh, "lsblk -f")
        if not re.search(r'crypto_LUKS', encryption_status):
            issues.append("Data at rest is not encrypted using LUKS or other encryption methods.")
        
        https_status = run_command(ssh, "grep 'listen 443' /etc/nginx/sites-enabled/default")
        if not re.search(r'listen\s+443', https_status):
            issues.append("HTTPS is not enabled for data in transit.")
        
        ssh.close()
        return issues
    
    except Exception as e:
        return [f"Error: {e}"]

def check_network_monitoring(hostname, username, password):
    """
    Connects to a remote Linux machine and checks for network monitoring tools.
    """
    issues = []
    try:
        ssh = create_ssh_client(hostname, username, password)
        print("Connection Successful!")
        
        monitoring_tools = run_command(ssh, r"dpkg -l | grep 'ntopng\|wireshark\|tcpdump'")
        if not re.search(r'ntopng|wireshark|tcpdump', monitoring_tools):
            issues.append("Network monitoring tools are not installed or active.")
        
        unusual_activity = run_command(ssh, "netstat -an")
        if re.search(r'ESTABLISHED\s+.*:22', unusual_activity):
            issues.append("Unusual network activity detected on port 22.")
        
        ssh.close()
        return issues
    
    except Exception as e:
        return [f"Error: {e}"]

def check_compliance(hostname, username, password):
    """
    Connects to the VM, retrieves firewall rules, and checks for compliance.
    """
    compliance_issues = {}
    
    issues = track_and_monitor_access(hostname, username, password)
    if issues:
        compliance_issues['track_and_monitor_access'] = issues
    
    issues = test_security_systems(hostname, username, password)
    if issues:
        compliance_issues['test_security_systems'] = issues
    
    issues = check_security_policy(hostname, username, password)
    if issues:
        compliance_issues['check_security_policy'] = issues
    
    firewall_rules, issues = get_firewall_rules(hostname, username, password)
    if issues:
        compliance_issues['get_firewall_rules'] = issues
    compliance_status, issues = analyze_firewall_rules(firewall_rules)
    if issues:
        compliance_issues['analyze_firewall_rules'] = issues
    
    issues = check_default_passwords()
    if issues:
        compliance_issues['check_default_passwords'] = issues
    
    issues = check_encryption(hostname, username, password)
    if issues:
        compliance_issues['check_encryption'] = issues
    
    issues = check_network_monitoring(hostname, username, password)
    if issues:
        compliance_issues['check_network_monitoring'] = issues
    
    return compliance_issues

# Example usage
hostname = '20.244.90.235'
username = 'ansh'
password = 'MinorProject@123'
compliance_issues = check_compliance(hostname, username, password)
print(json.dumps(compliance_issues, indent=4))
