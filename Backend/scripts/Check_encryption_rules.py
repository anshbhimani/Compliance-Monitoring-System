import logging

# Configure logging to include filename and line number
logging.basicConfig(level=logging.INFO,filename='LogFile.log',filemode='a',format='%(asctime)s - %(levelname)s - File: %(filename)s , Line: %(lineno)d - %(message)s')


# Define directories based on compliance requirements
COMPLIANCE_DIRECTORIES = {
    'PCI_DSS': ['/var/lib/mysql', '/etc/pki/tls/private', '/etc/pki/tls/certs'],
    'HIPAA': ['/home/user/medical_records', '/var/logs/hipaa_logs'],
    'GDPR': ['/home/user/personal_data', '/var/logs/gdpr_logs'],
    'NIST': ['/etc/ssl', '/var/lib/secure_data'],
    'SOX': ['/home/user/financial_data', '/var/logs/sox_logs'],
    'FISMA': ['/etc/security/fisma', '/var/federal/data'],
    'ISO_27001': ['/etc/iso27001/policies', '/home/user/pii_data']
}

def run_sudo_command(ssh, command, password):
    """Run a command with sudo privileges and handle password input."""
    try:
        stdin, stdout, stderr = ssh.exec_command(f"sudo -S {command}")
        stdin.write(password + "\n")  # Provide the password
        stdin.flush()
        return stdout.read().decode('utf-8')
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        return f"Error executing command: {e}"

def check_ssl_configuration(ssh, password):
    """Check SSL/TLS configuration for various web servers."""
    server_type = detect_server_type(ssh, password)

    if server_type == 'apache':
        command = "apachectl -S"
    elif server_type == 'nginx':
        command = "nginx -T | grep -i ssl"
    elif server_type == 'lighttpd':
        command = "lighttpd -f /etc/lighttpd/lighttpd.conf -t"
    else:
        logging.warning("Unknown or unsupported web server.")
        return "Unknown or unsupported web server."

    output = run_sudo_command(ssh, command, password)
    if "SSL" in output or "secure" in output:
        logging.info(f"{server_type.capitalize()} is configured with SSL/TLS.")
        return f"{server_type.capitalize()} is configured with SSL/TLS."
    else:
        logging.warning(f"{server_type.capitalize()} is NOT configured with SSL/TLS.")
        return f"{server_type.capitalize()} is NOT configured with SSL/TLS."

def detect_server_type(ssh, password):
    """Detect the web server type running on the machine."""
    try:
        # Check for Apache
        output = run_sudo_command(ssh, "apache2 -v 2>/dev/null || httpd -v 2>/dev/null", password)
        if "Apache" in output:
            return 'apache'
        
        # Check for Nginx
        output = run_sudo_command(ssh, "nginx -v 2>/dev/null", password)
        if "nginx" in output:
            return 'nginx'

        # Check for Lighttpd
        output = run_sudo_command(ssh, "lighttpd -v 2>/dev/null", password)
        if "Lighttpd" in output:
            return 'lighttpd'

        return 'unknown'

    except Exception as e:
        logging.error(f"Error detecting server type: {e}")
        return 'unknown'

def check_directory_encryption(ssh, directory, password):
    """Check if the specified directory is encrypted on the remote machine."""
    command = f"lsblk -f | grep '{directory}'"
    output = run_sudo_command(ssh, command, password)
    if "crypt" in output:
        logging.info(f"{directory} is encrypted (data at rest).")
        return f"{directory} is encrypted (data at rest)."
    else:
        logging.warning(f"{directory} is NOT encrypted (data at rest).")
        return f"{directory} is NOT encrypted (data at rest)."

def check_compliance_directories(ssh, compliance, password):
    """Check directories specific to a compliance framework for encryption."""
    directories = COMPLIANCE_DIRECTORIES.get(compliance, [])
    results = []
    
    if directories:
        logging.info(f"Checking encryption for {compliance} compliance.")
        for directory in directories:
            result = check_directory_encryption(ssh, directory, password)
            results.append(result)
    else:
        logging.warning(f"No specific directories defined for {compliance}.")
        results.append(f"No specific directories defined for {compliance}.")
    
    return results

def check_ssh_encryption(ssh, password):
    """Check if SSH is configured to use strong encryption algorithms."""
    command = "sshd -T | grep -E 'ciphers|macs'"
    output = run_sudo_command(ssh, command, password)
    if "aes256" in output or "aes128" in output:
        logging.info("SSH is using strong encryption algorithms.")
        return "SSH is using strong encryption algorithms."
    else:
        logging.warning("SSH is NOT using strong encryption algorithms.")
        return "SSH is NOT using strong encryption algorithms."

def run_checks(ssh, password):
    """
    Perform a series of compliance checks and log the results.
    """
    try:
        results = []

        # List of compliances to check
        compliances_to_check = ['PCI_DSS', 'HIPAA', 'GDPR', 'NIST', 'SOX', 'FISMA', 'ISO_27001']

        # Check directory encryption for each compliance
        for compliance in compliances_to_check:
            results.append((f"Checking directories for {compliance}", check_compliance_directories(ssh, compliance, password)))

        # Check SSL/TLS configuration
        results.append(("SSL Configuration", check_ssl_configuration(ssh, password)))

        # Check SSH encryption
        results.append(("SSH Encryption", check_ssh_encryption(ssh, password)))

        # Log the results
        for title, issues in results:
            logging.info(f"{title}: {issues}")
            
        return results

    finally:
        ssh.close()
