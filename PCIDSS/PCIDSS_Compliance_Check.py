import paramiko
import os
import logging
from mysql.connector import connect, Error
from dotenv import load_dotenv
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import re

# Set up logging
logging.basicConfig(filename='pci_dss_compliance_log.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()

# Load environment variables for SSH and MySQL
SSH_HOSTNAME = os.getenv('SSH_HOSTNAME')
SSH_USERNAME = os.getenv('SSH_USERNAME')
SSH_PASSWORD = os.getenv('SSH_PASSWORD')
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

# Establish SSH connection
def create_ssh_client(hostname, username, password):
    """Create and return an SSH client connection to the remote machine"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)
        logging.info("SSH connection established.")
        return ssh
    except paramiko.AuthenticationException as e:
        logging.error(f"Authentication failed: {e}")
        raise
    except Exception as e:
        logging.error(f"SSH connection failed: {e}")
        raise

# Run a command on the remote machine
def run_remote_command(ssh_client, command):
    """Run a shell command on the remote machine via SSH"""
    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode()
    return output.strip()

# Check 1: Verify SSH connection security
def check_ssh_connection(ssh_client):
    description = "Ensure that the SSH connection to the server is secure."
    remedy = "Verify SSH credentials and ensure that the server is accessible. Enable key-based authentication."
    try:
        ssh_client.exec_command('ls')
        logging.info("SSH connection is working.")
        return "SSH connection", description, "Passed", ""
    except Exception as e:
        failure_reason = f"SSH connection test failed: {e}"
        logging.error(failure_reason)
        return "SSH connection", description, "Failed", remedy

# Check 2: MySQL database connectivity
def check_mysql_connection():
    description = "Ensure that the system can connect to the MySQL database."
    remedy = "Check the database credentials and ensure the MySQL server is running."
    try:
        connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        logging.info("MySQL connection established.")
        connection.close()
        return "MySQL connection", description, "Passed", ""
    except Error as e:
        failure_reason = f"MySQL connection failed: {e}"
        logging.error(failure_reason)
        return "MySQL connection", description, "Failed", remedy


def test_security_systems(ssh):
    """
    Connects to a remote Linux machine via SSH and performs security system tests.
    """
    issues = []
    description = "Verify that security systems are active."
    try:
        ids_ips_status = run_remote_command(ssh, "systemctl status snort")
        if not re.search(r'active \(running\)', ids_ips_status):
            issues.append("IDS/IPS (snort) is not running or not active.")

        status = "Passed" if not issues else "Failed"
        return "Security Systems Test", description, status, "; ".join(issues)
    
    except Exception as e:
        logging.error(f"Error in test_security_systems: {e}")
        return "Security Systems Test", description, "Failed", f"Error: {e}"
    
def get_firewall_rules(ssh):
    """
    Connects to a remote Linux machine and retrieves detailed firewall rules using iptables.
    """
    issues = []
    logging.info("SSH connection established to retrieve firewall rules.")
    
    # Retrieve all iptables rules in a detailed format
    rules = run_remote_command(ssh, "iptables -L -n -v --line-numbers")
    
    # Retrieve NAT table rules
    nat_rules = run_remote_command(ssh, "iptables -t nat -L -n -v --line-numbers")
    
    # Retrieve mangle table rules
    mangle_rules = run_remote_command(ssh, "iptables -t mangle -L -n -v --line-numbers")
    
    # Retrieve raw table rules
    raw_rules = run_remote_command(ssh, "iptables -t raw -L -n -v --line-numbers")

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
    
    status = "Passed" if not issues else "Failed"
    description = "Ensure that firewall rules are in place to protect cardholder data."
    remedy = "Review firewall rules to ensure appropriate configurations."

    return "Firewall rules check", description, status, "; ".join(issues) if issues else remedy

def analyze_firewall_rules(all_rules):
    """
    Analyzes detailed firewall rules to determine compliance status.
    """
    issues = []
    compliance_status = 'unknown'
    
    if all_rules is None:
        issues.append("Firewall rules could not be retrieved.")
        compliance_status = 'non-compliant'
    else:
        filter_rules = all_rules.get('filter_rules', '')

        # Check for specific port rules
        if 'ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22' in filter_rules:
            compliance_status = 'compliant'
        else:
            issues.append("No rule found allowing SSH (port 22).")
            compliance_status = 'non-compliant'

    status = "Passed" if compliance_status == 'compliant' else "Failed"
    description = "Analyze firewall rules for compliance with PCI DSS requirements."
    remedy = "Ensure SSH (port 22) is allowed in firewall rules."

    return "Firewall rules analysis", description, status, "; ".join(issues) if issues else remedy


def check_encryption(ssh_client):
    description = "Ensure that encryption is used to protect cardholder data in transit."
    remedy = "Implement SSL/TLS for all data transmissions that involve cardholder data."
    try:
        result = run_remote_command(ssh_client, 'grep -i "SSL" /etc/nginx/nginx.conf')  # Example for Nginx
        if "ssl" in result.lower():
            logging.info("SSL/TLS encryption is enabled for data transmission.")
            return "Encryption of cardholder data", description, "Passed", ""
        else:
            failure_reason = "SSL/TLS encryption not found in configuration."
            logging.warning(failure_reason)
            return "Encryption of cardholder data", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check encryption settings: {e}"
        logging.error(failure_reason)
        return "Encryption of cardholder data", description, "Failed", remedy

def check_user_access_control():
    description = "Ensure proper access controls are in place to protect cardholder data."
    remedy = "Implement role-based access control (RBAC) for restricting access to cardholder data."
    try:
        query = "SELECT * FROM user_roles WHERE role = 'admin';"  # Example query
        connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        connection.close()

        if result:
            logging.info("User access control mechanisms found.")
            return "User access control", description, "Passed", ""
        else:
            failure_reason = "User access control mechanisms not found."
            logging.warning(failure_reason)
            return "User access control", description, "Failed", remedy
    except Error as e:
        failure_reason = f"MySQL error during user access control check: {e}"
        logging.error(failure_reason)
        return "User access control", description, "Failed", remedy


def check_network_monitoring(hostname, username, password):
    """
    Connects to a remote Linux machine and checks for network monitoring tools.
    """
    issues = []
    description = "Ensure that network monitoring tools are installed and active."
    remedy = "Install network monitoring tools to detect and log network activity."
    
    try:
        ssh = create_ssh_client(hostname, username, password)
        logging.info("SSH connection established for network monitoring check.")
        
        monitoring_tools = run_remote_command(ssh, r"dpkg -l | grep 'ntopng\|wireshark\|tcpdump'")
        if not re.search(r'ntopng|wireshark|tcpdump', monitoring_tools):
            issues.append("Network monitoring tools are not installed or active.")
        
        unusual_activity = run_remote_command(ssh, "netstat -an")
        if re.search(r'ESTABLISHED\s+.*:22', unusual_activity):
            issues.append("Unusual network activity detected on port 22.")
        
        ssh.close()
        status = "Passed" if not issues else "Failed"
        return "Network Monitoring Check", description, status, "; ".join(issues)
    
    except Exception as e:
        logging.error(f"Error in check_network_monitoring: {e}")
        return "Network Monitoring Check", description, "Failed", f"Error: {e}"


    
# Check 3: Verify existence of firewall and security policies
def check_firewall(ssh_client):
    description = "Ensure that firewalls are implemented to protect cardholder data."
    remedy = "Configure firewalls to restrict inbound and outbound traffic to only what is necessary."
    try:
        result = run_remote_command(ssh_client, 'iptables -L')  # Check iptables configuration
        if "Chain" in result:
            logging.info("Firewall rules are in place.")
            return "Firewall configuration", description, "Passed", ""
        else:
            failure_reason = "Firewall rules not found."
            logging.warning(failure_reason)
            return "Firewall configuration", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check firewall configuration: {e}"
        logging.error(failure_reason)
        return "Firewall configuration", description, "Failed", remedy

# Check 4: Verify encryption for transmission of cardholder data
def check_encryption(ssh_client):
    description = "Ensure that encryption is used to protect cardholder data in transit."
    remedy = "Implement SSL/TLS for all data transmissions that involve cardholder data."
    try:
        result = run_remote_command(ssh_client, 'grep -i "SSL" /etc/nginx/nginx.conf')  # Example for Nginx
        if "ssl" in result.lower():
            logging.info("SSL/TLS encryption is enabled for data transmission.")
            return "Encryption of cardholder data", description, "Passed", ""
        else:
            failure_reason = "SSL/TLS encryption not found in configuration."
            logging.warning(failure_reason)
            return "Encryption of cardholder data", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check encryption settings: {e}"
        logging.error(failure_reason)
        return "Encryption of cardholder data", description, "Failed", remedy

# Check 5: Verify user access controls for cardholder data
def check_user_access_control():
    description = "Ensure proper access controls are in place to protect cardholder data."
    remedy = "Implement role-based access control (RBAC) for restricting access to cardholder data."
    try:
        query = "SELECT * FROM user_roles WHERE role = 'admin';"  # Example query
        connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        connection.close()

        if result:
            logging.info("User access control mechanisms found.")
            return "User access control", description, "Passed", ""
        else:
            failure_reason = "User access control mechanisms not found."
            logging.warning(failure_reason)
            return "User access control", description, "Failed", remedy
    except Error as e:
        failure_reason = f"MySQL error during user access control check: {e}"
        logging.error(failure_reason)
        return "User access control", description, "Failed", remedy

# Check 6: Verify logging and monitoring mechanisms
def check_logging(ssh_client):
    description = "Ensure logging mechanisms are in place to track access to cardholder data."
    remedy = "Implement logging for access to cardholder data and regularly review these logs."
    try:
        result = run_remote_command(ssh_client, 'cat /var/log/syslog')  # Change path if necessary
        if "cardholder" in result.lower():
            logging.info("Logging for cardholder data access found.")
            return "Logging for cardholder data access", description, "Passed", ""
        else:
            failure_reason = "Logging for cardholder data access not found."
            logging.warning(failure_reason)
            return "Logging for cardholder data access", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check logging mechanisms: {e}"
        logging.error(failure_reason)
        return "Logging for cardholder data access", description, "Failed", remedy

# Check 7: Verify vulnerability management program
def check_vulnerability_management(ssh_client):
    description = "Ensure that a vulnerability management program is in place."
    remedy = "Conduct regular vulnerability scans and ensure that all systems are patched."
    try:
        result = run_remote_command(ssh_client, 'cat /etc/issue')  # Check for OS version and patches
        if "Ubuntu" in result or "Debian" in result:  # Adjust as necessary for your OS
            logging.info("Vulnerability management program found.")
            return "Vulnerability management", description, "Passed", ""
        else:
            failure_reason = "Vulnerability management program not found."
            logging.warning(failure_reason)
            return "Vulnerability management", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check vulnerability management: {e}"
        logging.error(failure_reason)
        return "Vulnerability management", description, "Failed", remedy

# Generate PDF report
# Generate PDF report with improved formatting
def generate_pdf_report(checks):
    pdf_filename = "PCIDSS_Compliance_Report.pdf"
    doc = SimpleDocTemplate(
        pdf_filename, 
        pagesize=A4, 
        rightMargin=0.5*inch, 
        leftMargin=0.5*inch, 
        topMargin=1*inch, 
        bottomMargin=1*inch
    )
    elements = []

    # Define styles
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    table_header_style = styles['Heading4']
    
    # Add Title
    elements.append(Paragraph("PCIDSS Compliance Report", title_style))
    elements.append(Spacer(1, 0.5 * inch))

    # Add a section heading for the table
    elements.append(Paragraph("Compliance Check Results", heading_style))
    elements.append(Spacer(1, 0.3 * inch))

    # Define table headers and their styling
    table_data = [
        [
            Paragraph("<b>Check</b>", table_header_style),
            Paragraph("<b>Description</b>", table_header_style),
            Paragraph("<b>Result</b>", table_header_style),
            Paragraph("<b>Remedy (if failed)</b>", table_header_style)
        ]
    ]

    # Add each compliance check result to the table
    for check in checks:
        check_name = Paragraph(check[0], normal_style)
        description = Paragraph(check[1], normal_style)
        result = Paragraph(f"<b>{check[2]}</b>", normal_style)
        remedy = Paragraph(check[3], normal_style) if check[2] == "Failed" else Paragraph("N/A", normal_style)
        
        # Add the check's row to the table
        table_data.append([check_name, description, result, remedy])

    # Define table layout, column widths, and formatting
    table = Table(table_data, colWidths=[1 * inch, 2 * inch, 1 * inch, 3 * inch])
    
    # Define the table style
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#4F81BD")),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header font
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.beige, colors.lightgrey]),  # Alternating row colors
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('ALIGN', (2, 1), (2, -1), 'CENTER'),  # Center align the "Result" column
        ('VALIGN', (0, 1), (-1, -1), 'TOP'),
        ('TEXTCOLOR', (2, 1), (2, -1), colors.green),  # Green text for "Passed"
        ('TEXTCOLOR', (2, 1), (2, -1), colors.red),    # Red text for "Failed"
    ]))

    # Add the table to the document
    elements.append(table)

    # Build the PDF
    doc.build(elements)
    print(f"PDF report generated: {pdf_filename}")
    logging.info(f"PDF report generated: {pdf_filename}")
    
# Main compliance check function
def run_compliance_checks():
    checks = []
    try:
        ssh_client = create_ssh_client(SSH_HOSTNAME, SSH_USERNAME, SSH_PASSWORD)
        
        # Collect results from each check
        checks.append(check_ssh_connection(ssh_client))
        checks.append(check_mysql_connection())
        checks.append(check_firewall(ssh_client))
        checks.append(check_encryption(ssh_client))
        checks.append(check_user_access_control())
        checks.append(check_logging(ssh_client))
        checks.append(check_vulnerability_management(ssh_client))
        
        # Include the additional checks you implemented
        checks.append(test_security_systems(ssh_client))
        firewall_rules, firewall_issues = get_firewall_rules(ssh_client)
        checks.append(analyze_firewall_rules(firewall_rules))
        checks.append(check_encryption(SSH_HOSTNAME, SSH_USERNAME, SSH_PASSWORD))  # Ensure encryption checks are included
        checks.append(check_network_monitoring(SSH_HOSTNAME, SSH_USERNAME, SSH_PASSWORD))  # Ensure network monitoring checks are included
        
        ssh_client.close()
    except Exception as e:
        logging.error(f"Compliance check failed: {e}")
    
    generate_pdf_report(checks)

# Execute compliance checks
if __name__ == "__main__":
    run_compliance_checks()
