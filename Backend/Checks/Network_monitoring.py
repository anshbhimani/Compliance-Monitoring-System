import re
import logging
import time

# Define common network monitoring commands
CHECK_PORTS_COMMAND = "sudo ss -tuln"  # Check active ports and listening services
CHECK_FIREWALL_COMMAND = "sudo iptables -S"  # Check firewall rules
CHECK_AUTH_LOGS = "/var/log/auth.log"  # Authentication logs
CHECK_TCPDUMP_COMMAND = "sudo tcpdump -i any -n -c 100"  # Capture network packets (first 100)
CHECK_NTP_STATUS = "sudo ntpq -p"  # Check NTP status
CHECK_DNS_STATUS = "cat /etc/resolv.conf"  # Check DNS configurations
CHECK_HTTP_PORTS = "curl -Is http://localhost"  # Check HTTP service
CHECK_HTTPS_PORTS = "curl -Is https://localhost"  # Check HTTPS service
CHECK_DB_CONNECTIONS = "sudo ss -tnp | grep LISTEN | grep -E 'mysql|postgresql|mongodb|cassandra|sqlite|redis|mariadb'"  # Check active DB connections
CHECK_ACTIVE_SSH_USERS = "who | grep -c 'pts'"  # Count active SSH users

logging.basicConfig(level=logging.INFO, filename='LogFile.log', filemode='a', format='%(asctime)s - %(levelname)s - File: %(filename)s , Line: %(lineno)d - %(message)s')

def print_and_log(message):
    """Utility function to log and print messages."""
    logging.info(message)
    print(message)

def run_sudo_command(ssh, command, password):
    """Run a command with sudo privileges and handle password input."""
    try:
        stdin, stdout, stderr = ssh.exec_command(f"sudo -S {command}")
        stdin.write(password + "\n")  # Provide the password
        stdin.flush()
        return stdout.read().decode('utf-8')
    except Exception as e:
        return f"Error executing command: {e}"

def check_active_ports(ssh, password):
    """Check for active listening ports and services."""
    ports_output, _ = run_sudo_command(ssh, CHECK_PORTS_COMMAND, password)
    message = f"Active Listening Ports:\n{ports_output}"
    print_and_log(message)

    issues = []
    if re.search(r':80\s+.*LISTEN', ports_output):
        issues.append("Port 80 (HTTP) is open: ensure it's necessary and secure.")
    if re.search(r':443\s+.*LISTEN', ports_output):
        issues.append("Port 443 (HTTPS) is open: ensure proper SSL/TLS configurations.")
    if re.search(r':22\s+.*LISTEN', ports_output):
        issues.append("Port 22 (SSH) is open: ensure strong authentication mechanisms.")
    if re.search(r':\d{1,5}\s+.*LISTEN', ports_output):
        issues.append("Unexpected open ports detected: review for security risks.")

    return "Active Ports Check", ": ".join(issues) if issues else "No issues found with active ports."

def check_firewall_rules(ssh, password):
    """Retrieve and analyze firewall rules."""
    firewall_output, _ = run_sudo_command(ssh, CHECK_FIREWALL_COMMAND, password)
    message = f"Firewall Rules:\n{firewall_output}"
    print_and_log(message)

    issues = []
    if not re.search(r'-A INPUT -j ACCEPT', firewall_output):
        issues.append("Firewall should default to deny all inbound traffic.")
    if not re.search(r'-A OUTPUT -j ACCEPT', firewall_output):
        issues.append("Firewall should default to deny all outbound traffic.")
    if not re.search(r'-A INPUT -p tcp --dport 22 -j ACCEPT', firewall_output):
        issues.append("No rule found allowing SSH (port 22).")
    if re.search(r'-A INPUT -p tcp --dport \d+ -j REJECT', firewall_output):
        issues.append("Unnecessary REJECT rules found in firewall configuration.")

    return "Firewall Rules Check", ": ".join(issues) if issues else "Firewall rules are appropriately configured."

def analyze_network_logs(ssh, password):
    """Install Wireshark and continuously analyze network traffic for compliance issues."""
    install_command = "sudo apt-get update && sudo apt-get install -y wireshark"
    run_sudo_command(ssh, install_command, password)
    print_and_log("Wireshark installed successfully.")

    command = "tshark -i any -T fields -e frame.time -e ip.src -e ip.dst -e tcp.port -e http.request.uri"
    print_and_log("Starting continuous network traffic analysis...")
    
    try:
        issues_found = []
        
        while True:
            network_logs, _ = run_sudo_command(ssh, command, password)
            message = f"Network Traffic Analysis:\n{network_logs}"
            print_and_log(message)

            if re.search(r'Failed password', network_logs):
                issues_found.append("Failed login attempts detected: review security logs for potential breaches.")
            if re.search(r'Connection closed by', network_logs):
                issues_found.append("Unexpected connection closures detected: review for anomalies.")
            if re.search(r'suspicious_pattern', network_logs):  # Replace with a real pattern
                issues_found.append("Potential data exfiltration attempt detected: investigate further.")

            if issues_found:
                print_and_log("Compliance Issues Found: " + ": ".join(issues_found))
            else:
                print_and_log("No critical issues found in network traffic.")

            time.sleep(60)  # Analyze every 60 seconds

    except Exception as e:
        print_and_log(f"Error during network traffic analysis: {str(e)}")

    return "Network Log Analysis", ": ".join(issues_found) if issues_found else "No issues found in network traffic."

def check_authentication_logs(ssh, password):
    """Check authentication logs for user access control issues."""
    command = f"sudo tail -n 100 {CHECK_AUTH_LOGS}"
    auth_logs, _ = run_sudo_command(ssh, command, password)
    message = f"Authentication Logs Analysis:\n{auth_logs}"
    print_and_log(message)

    issues = []
    if re.search(r'Failed password for', auth_logs):
        issues.append("Multiple failed authentication attempts detected: potential security risk.")
    if re.search(r'root.*login', auth_logs):
        issues.append("Direct root login attempts detected: consider disabling root SSH access.")
    if re.search(r'PAM:authentication failure', auth_logs):
        issues.append("PAM authentication failures detected: review for potential attacks.")

    return "Authentication Log Analysis", ": ".join(issues) if issues else "No issues found in authentication logs."

def check_unencrypted_data_flow(ssh, password):
    """Check for unencrypted data flows in network traffic."""
    print_and_log("Checking for unencrypted data flows...")
    packet_capture_output, _ = run_sudo_command(ssh, CHECK_TCPDUMP_COMMAND, password)
    message = f"Packet Capture Output:\n{packet_capture_output}"
    print_and_log(message)

    issues = []
    if re.search(r'HTTP', packet_capture_output):
        issues.append("Unencrypted HTTP traffic detected: consider enforcing HTTPS.")
    if re.search(r'ftp', packet_capture_output):
        issues.append("Unencrypted FTP traffic detected: consider using SFTP or FTPS.")
    if re.search(r'smtp', packet_capture_output):
        issues.append("Unencrypted SMTP traffic detected: consider using SMTPS.")
    if re.search(r'password', packet_capture_output, re.IGNORECASE):
        issues.append("Plaintext passwords detected in network traffic: ensure encryption.")

    return "Unencrypted Data Flow Check", ": ".join(issues) if issues else "No unencrypted data flows detected."

def check_ntp_status(ssh, password):
    """Check the status of NTP service for time synchronization."""
    ntp_output, _ = run_sudo_command(ssh, CHECK_NTP_STATUS, password)
    message = f"NTP Status:\n{ntp_output}"
    print_and_log(message)

    issues = []
    if not re.search(r'^\s*server\s+', ntp_output):
        issues.append("NTP servers not configured: system may have incorrect time settings.")
    if re.search(r'\*\s+(\S+)', ntp_output):
        issues.append("NTP synchronization is not accurate: check NTP settings.")

    return "NTP Status Check", ": ".join(issues) if issues else "NTP service is properly configured."

def check_dns_configuration(ssh, password):
    """Check DNS configuration for security and reliability."""
    dns_output, _ = run_sudo_command(ssh, CHECK_DNS_STATUS, password)
    message = f"DNS Configuration:\n{dns_output}"
    print_and_log(message)

    issues = []
    if not re.search(r'nameserver\s+\d+\.\d+\.\d+\.\d+', dns_output):
        issues.append("No nameservers configured: DNS resolution may fail.")

    return "DNS Configuration Check", ": ".join(issues) if issues else "DNS configuration is properly set."

def check_http_service(ssh, password):
    """Check the availability of the HTTP service."""
    http_output, _ = run_sudo_command(ssh, CHECK_HTTP_PORTS, password)
    message = f"HTTP Service Check:\n{http_output}"
    print_and_log(message)

    issues = []
    if "200 OK" not in http_output:
        issues.append("HTTP service is down: ensure the web server is running.")

    return "HTTP Service Check", ": ".join(issues) if issues else "HTTP service is running fine."

def check_https_service(ssh, password):
    """Check the availability of the HTTPS service."""
    https_output, _ = run_sudo_command(ssh, CHECK_HTTPS_PORTS, password)
    message = f"HTTPS Service Check:\n{https_output}"
    print_and_log(message)

    issues = []
    if "200 OK" not in https_output:
        issues.append("HTTPS service is down: ensure SSL/TLS configurations are correct.")

    return "HTTPS Service Check", ": ".join(issues) if issues else "HTTPS service is running fine."

def check_db_connections(ssh, password):
    """Check active database connections and listening services."""
    db_output, _ = run_sudo_command(ssh, CHECK_DB_CONNECTIONS, password)
    message = f"Database Connections Check:\n{db_output}"
    print_and_log(message)

    issues = []
    if re.search(r'LISTEN', db_output):
        issues.append("Database is listening on a public interface: restrict access to localhost.")

    return "Database Connections Check", ": ".join(issues) if issues else "Database connections are secure."

def check_active_ssh_users(ssh, password):
    """Count active SSH users to ensure access control."""
    active_users_output, _ = run_sudo_command(ssh, CHECK_ACTIVE_SSH_USERS, password)
    message = f"Active SSH Users Count:\n{active_users_output}"
    print_and_log(message)

    issues = []
    if int(active_users_output) > 5:  # Threshold for active SSH users
        issues.append("Too many active SSH users detected: review access control policies.")

    return "Active SSH Users Check", ": ".join(issues) if issues else "Active SSH user count is within acceptable limits."

def check_database_connections(ssh,password):
    """
    Check for active database connections.
    """
    db_output, _ = run_sudo_command(ssh,CHECK_DB_CONNECTIONS,password)
    logging.info(f"Active Database Connections:\n{db_output}")

    issues = []
    if re.search(r'LISTEN', db_output):
        issues.append("Active database connections detected; ensure they are necessary and secure.")

    return "Database Connection Check", ": ".join(issues) if issues else "No active database connections detected."

def compliance_report(ssh, password):
    """Compile and print the compliance report for security checks."""
    print_and_log("Starting compliance checks...\n")

    checks = [
        check_active_ports(ssh, password),
        check_firewall_rules(ssh, password),
        analyze_network_logs(ssh, password),
        check_authentication_logs(ssh, password),
        check_unencrypted_data_flow(ssh, password),
        check_ntp_status(ssh, password),
        check_dns_configuration(ssh, password),
        check_http_service(ssh, password),
        check_https_service(ssh, password),
        check_db_connections(ssh, password),
        check_active_ssh_users(ssh, password),
        check_database_connections(ssh,password)
    ]

    for title, issues in checks:
        print_and_log(f"{title}: {issues}\n")

def run_checks(ssh,password):
    """
    Perform a series of network checks and log the results.
    """
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        results = []

        results.append("Active Ports Check: " + check_active_ports(ssh, password))  # Check for active listening ports and services
        results.append("Firewall Rules Check: " + check_firewall_rules(ssh, password))  # Analyze firewall rules for security configurations
        results.append("Network Log Analysis: " + analyze_network_logs(ssh, password))  # Continuous analysis of network traffic for compliance issues
        results.append("Authentication Logs Analysis: " + check_authentication_logs(ssh, password))  # Review authentication logs for user access control issues
        results.append("Unencrypted Data Flow Check: " + check_unencrypted_data_flow(ssh, password))  # Check for unencrypted data flows in network traffic
        results.append("NTP Status Check: " + check_ntp_status(ssh, password))  # Check the status of NTP service for time synchronization
        results.append("DNS Configuration Check: " + check_dns_configuration(ssh, password))  # Review DNS configuration for security and reliability
        results.append("HTTP Service Check: " + check_http_service(ssh, password))  # Check the availability of the HTTP service
        results.append("HTTPS Service Check: " + check_https_service(ssh, password))  # Check the availability of the HTTPS service
        results.append("Database Connections Check: " + check_database_connections(ssh, password))  # Check active database connections for security
        results.append("Active SSH Users Check: " + check_active_ssh_users(ssh, password))  # Count active SSH users and review access


        for title, issues in results:
            print_and_log(f"{title}: {issues}\n")
            
        return {"status": "success", "results": results}
    
    except Exception as e:
        logging.error(f"Error in run_checks: {str(e)}")
        return {"error": f"Error from Network_Monitoring.py: {str(e)}"}, 500
    finally:
        ssh.close()
