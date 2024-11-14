import paramiko
import logging
import re
import json
import os

logging.basicConfig(level=logging.INFO,filename='LogFile.log',filemode='a',format='%(asctime)s - %(levelname)s - File: %(filename)s , Line: %(lineno)d - %(message)s')


# Define common system directories and files for user access control checks
COMMON_USER_ACCESS_FILES = [
    '/etc/passwd',           # User account information
    '/etc/shadow',          # User password hashes
    '/etc/sudoers',         # Sudo access configuration
    '/etc/login.defs',      # User account defaults
    '/etc/security/access.conf',  # Access control lists
    '/etc/group',           # Group account information
    '/etc/gshadow',         # Group password hashes
    '/etc/ssh/sshd_config', # SSH server configuration
    '/var/log/auth.log',    # Authentication logs
    '/var/log/secure',      # Security logs (CentOS, RHEL)
    '/var/log/syslog',      # General system logs
]

# Define common software logs (databases, ELK stack, etc.)
SOFTWARE_LOGS = {
    'mysql': '/var/log/mysql/error.log',
    'postgresql': '/var/log/postgresql/postgresql.log',
    'mongodb': '/var/log/mongodb/mongod.log',
    'elasticsearch': '/var/log/elasticsearch/elasticsearch.log',
    'logstash': '/var/log/logstash/logstash-plain.log',
    'kibana': '/var/log/kibana/kibana.log'
}

def check_file_permissions(ssh, filepath):
    """
    Check permissions of specified file to ensure they are appropriately restricted.
    """
    command = f"ls -l {filepath}"
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    logging.info(f"Permissions for {filepath}:\n{output}")

    # Check if permissions are overly permissive
    if '777' in output:
        return {"file": filepath, "result": "Warning", "message": f"{filepath} has overly permissive permissions (777)."}
    elif re.search(r'^[^r].* ', output):  # No read access for others
        return {"file": filepath, "result": "Alert", "message": f"{filepath} has restricted permissions."}
    else:
        return {"file": filepath, "result": "OK", "message": f"{filepath} permissions are appropriately restricted."}

def analyze_logs_for_compliance(ssh, log_path):
    """
    Analyze logs for compliance issues, looking for specific patterns.
    """
    command = f"tail -n 100 {log_path}"
    stdin, stdout, stderr = ssh.exec_command(command)
    logs = stdout.read().decode('utf-8')

    issues = []

    # Check for critical compliance issues in logs
    if re.search(r'unencrypted', logs, re.IGNORECASE):
        issues.append("Unencrypted data detected in logs, violates PCI DSS and GDPR.")
    if re.search(r'user data', logs, re.IGNORECASE):
        issues.append("User data processing detected; ensure consent for GDPR compliance.")
    if re.search(r'authentication failed', logs, re.IGNORECASE):
        issues.append("Multiple failed login attempts detected; potential security breach (HIPAA, PCI DSS).")
    if re.search(r'root\s+.*NOPASSWD', logs):
        issues.append("Sudo access granted without password; violates security best practices.")
    if re.search(r'Unauthorized|denied|access', logs, re.IGNORECASE):
        issues.append("Unauthorized access attempts detected; review access policies.")

    if not issues:
        return {"log": log_path, "result": "OK", "message": "Log analysis shows no critical issues."}
    else:
        return {"log": log_path, "result": "Issues Found", "message": "; ".join(issues)}

def check_password_policy(ssh):
    """
    Check password policy configurations for compliance.
    """
    command = "cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|ENCRYPT_METHOD'"
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    logging.info(f"Password Policy:\n{output}")

    issues = []
    
    if "PASS_MAX_DAYS" not in output or re.search(r'[^0-9]', output.split("PASS_MAX_DAYS")[-1]):
        issues.append("Missing or invalid maximum password age (PASS_MAX_DAYS).")
    if "PASS_MIN_LEN" not in output or re.search(r'[^0-9]', output.split("PASS_MIN_LEN")[-1]):
        issues.append("Missing or invalid minimum password length (PASS_MIN_LEN).")
    if "PASS_WARN_AGE" not in output:
        issues.append("Missing password warning age (PASS_WARN_AGE).")
    if "ENCRYPT_METHOD" not in output:
        issues.append("Missing encryption method for passwords (ENCRYPT_METHOD).")

    return {
        "check": "Password Policy Check",
        "result": "Issues Found" if issues else "OK",
        "message": "; ".join(issues) if issues else "Password policy is properly configured."
    }
def check_account_lockout_policy(ssh):
    """
    Check if account lockout policies are enforced after failed login attempts.
    """
    command = "cat /etc/pam.d/common-auth | grep pam_tally2"
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    logging.info(f"Account Lockout Policy:\n{output}")

    if "deny=" in output:
        return {"check": "Account Lockout Policy", "result": "OK", "message": "Account lockout policy is properly configured."}
    else:
        return {"check": "Account Lockout Policy", "result": "Alert", "message": "Account lockout policy is NOT properly configured."}

def check_sudo_access(ssh):
    """
    Check sudo access policies to ensure privileged access is restricted.
    """
    command = "cat /etc/sudoers"
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    logging.info(f"Sudo Access Configuration:\n{output}")

    issues = []
    if re.search(r'NOPASSWD', output):
        issues.append("Sudo access without password is configured; potential security risk.")
    if re.search(r'^%admin|^root', output):
        issues.append("Sudo access for admin/root is present; ensure proper restrictions.")

    return {
        "check": "Sudo Access Check",
        "result": "Issues Found" if issues else "OK",
        "message": "; ".join(issues) if issues else "Sudo access is appropriately restricted."
    }
    
def run_checks(ssh, password):
    """
    Run all user access control checks and log their results.
    """
    results = {}

    # Check user access control files
    for filepath in COMMON_USER_ACCESS_FILES:
        result = check_file_permissions(ssh, filepath)
        results[filepath] = result

    # Check password policy
    password_policy_result = check_password_policy(ssh)
    results["password_policy"] = password_policy_result

    # Check account lockout policy
    lockout_policy_result = check_account_lockout_policy(ssh)
    results["account_lockout_policy"] = lockout_policy_result

    # Check sudo access policy
    sudo_access_result = check_sudo_access(ssh)
    results["sudo_access_policy"] = sudo_access_result

    # Check logs for critical compliance issues in popular software
    for software, log_path in SOFTWARE_LOGS.items():
        log_analysis_result = analyze_logs_for_compliance(ssh, log_path)
        results[software] = log_analysis_result

    return results

def main():
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    hostname =  os.environ['SSH_HOSTNAME']
    username = os.environ['SSH_USERNAME']
    password = os.environ['SSH_PASSWORD']

    try:
        # Establish SSH connection
        logging.info("Connecting to remote machine...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)

        # Run all checks and collect results
        results = run_checks(ssh)

         # Log the results as JSON
        json_results = json.dumps(results, indent=4)  # Convert results to JSON
        logging.info(f"Results:\n{json_results}")

        # Close SSH connection
        ssh.close()

    except Exception as e:
        logging.error(f"Failed to connect or execute commands: {e}")

if __name__ == "__main__":
    main()
