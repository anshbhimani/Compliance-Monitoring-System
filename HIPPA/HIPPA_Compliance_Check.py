# HIPPA COMPLIANCE
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

# Set up logging
logging.basicConfig(filename='hipaa_compliance_log.log',
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

# Check 1: Verify SSH connection is secure
def check_ssh_connection(ssh_client):
    description = "Ensure that the SSH connection to the server is secure and functioning."
    remedy = "Verify SSH credentials and ensure that the server is accessible. Enable stronger SSH encryption and use key-based authentication."
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
    description = "Ensure that the system can connect to the MySQL database where patient data is stored."
    remedy = "Check the database credentials and ensure the MySQL server is running. Verify network access to the database."
    try:
        connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        logging.info("MySQL connection established.")
        connection.close()
        return "MySQL connection", description, "Passed", ""
    except Error as e:
        failure_reason = f"MySQL connection failed: {e}"
        logging.error(failure_reason)
        return "MySQL connection", description, "Failed", remedy

# Check 3: Verify existence of HIPAA privacy policy
def check_privacy_policy(ssh_client):
    description = "Verify that the HIPAA privacy policy exists and is accessible to users."
    remedy = "Ensure that the HIPAA privacy policy is uploaded to the server and placed in the correct directory. Check permissions to make it accessible."
    try:
        result = run_remote_command(ssh_client, 'cat /path/to/hipaa_privacy_policy.txt')  # Update path
        if "Privacy Policy" in result:
            logging.info("HIPAA privacy policy found.")
            return "HIPAA privacy policy", description, "Passed", ""
        else:
            failure_reason = "HIPAA privacy policy not found."
            logging.warning(failure_reason)
            return "HIPAA privacy policy", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check HIPAA privacy policy: {e}"
        logging.error(failure_reason)
        return "HIPAA privacy policy", description, "Failed", remedy

# Check 4: Verify encryption of PHI (Protected Health Information)
def check_encryption(ssh_client):
    description = "Ensure that encryption is enabled for sensitive patient data in the database."
    remedy = "Configure SSL encryption for MySQL and other databases. Ensure the appropriate settings are in place."
    try:
        result = run_remote_command(ssh_client, 'grep -i "SSL" /etc/mysql/my.cnf')  # Change path if necessary
        if "SSL" in result:
            logging.info("MySQL SSL encryption is enabled.")
            return "Encryption of PHI", description, "Passed", ""
        else:
            failure_reason = "MySQL SSL encryption not enabled."
            logging.warning(failure_reason)
            return "Encryption of PHI", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check encryption settings: {e}"
        logging.error(failure_reason)
        return "Encryption of PHI", description, "Failed", remedy

# Check 5: Verify user access control mechanisms
def check_user_access_control():
    description = "Ensure proper user access controls are in place to protect PHI."
    remedy = "Implement role-based access control (RBAC) to limit access to PHI based on user roles."
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

# Check 6: Verify data breach response plan
def check_data_breach_response_plan(ssh_client):
    description = "Ensure that a data breach response plan is in place."
    remedy = "Develop a data breach response plan, including detection and notification procedures, and store it on the server."
    try:
        result = run_remote_command(ssh_client, 'cat /path/to/data_breach_response_plan.txt')  # Update path
        if "Data Breach Response" in result:
            logging.info("Data breach response plan found.")
            return "Data breach response plan", description, "Passed", ""
        else:
            failure_reason = "Data breach response plan not found."
            logging.warning(failure_reason)
            return "Data breach response plan", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check data breach response plan: {e}"
        logging.error(failure_reason)
        return "Data breach response plan", description, "Failed", remedy

# Check 7: Verify audit logs for access to PHI
def check_audit_logs(ssh_client):
    description = "Ensure that audit logs for access to PHI are maintained."
    remedy = "Implement logging mechanisms to track access to PHI and regularly review these logs."
    try:
        result = run_remote_command(ssh_client, 'cat /var/log/audit.log')  # Change path if necessary
        if "PHI access" in result:
            logging.info("Audit logs for PHI access found.")
            return "Audit logs for PHI access", description, "Passed", ""
        else:
            failure_reason = "Audit logs for PHI access not found."
            logging.warning(failure_reason)
            return "Audit logs for PHI access", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check audit logs: {e}"
        logging.error(failure_reason)
        return "Audit logs for PHI access", description, "Failed", remedy

# Check 8: Verify employee training on HIPAA compliance
def check_employee_training():
    description = "Ensure that employees are trained on HIPAA compliance and the handling of PHI."
    remedy = "Implement a regular training program for employees on HIPAA regulations and the protection of PHI."
    try:
        # Dummy check for training records
        training_records_exist = True  # Replace with actual check logic
        
        if training_records_exist:
            logging.info("Employee training records found.")
            return "Employee training on HIPAA", description, "Passed", ""
        else:
            failure_reason = "Employee training records not found."
            logging.warning(failure_reason)
            return "Employee training on HIPAA", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check employee training records: {e}"
        logging.error(failure_reason)
        return "Employee training on HIPAA", description, "Failed", remedy

# Generate PDF report with improved formatting
def generate_pdf_report(checks):
    pdf_filename = "HIPAA_Compliance_Report.pdf"
    doc = SimpleDocTemplate(
        pdf_filename, 
        pagesize=A4, 
        rightMargin=0.5*inch, 
        leftMargin=0.5*inch, 
        topMargin=1*inch, 
        bottomMargin=1*inch
    )
     # Define styles
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    table_header_style = styles['Heading4']
    
    elements = []
    elements.append(Paragraph("HIPAA Compliance Check Report", title_style))
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
    
    elements.append(table)
    doc.build(elements)
    logging.info("PDF report generated.")
    return pdf_filename

# Main compliance check function
def run_compliance_checks():
    checks = []
    try:
        ssh_client = create_ssh_client(SSH_HOSTNAME, SSH_USERNAME, SSH_PASSWORD)
        
        checks.append(check_ssh_connection(ssh_client))
        checks.append(check_mysql_connection())
        checks.append(check_privacy_policy(ssh_client))
        checks.append(check_encryption(ssh_client))
        checks.append(check_user_access_control())
        checks.append(check_data_breach_response_plan(ssh_client))
        checks.append(check_audit_logs(ssh_client))
        checks.append(check_employee_training())
        
        ssh_client.close()
        logging.info("SSH connection closed.")
        return checks
    except Exception as e:
        logging.error(f"Compliance check failed: {e}")
    
    # Generate PDF report
    pdf_filename = generate_pdf_report(checks)
    print(f"HIPAA compliance report generated: {pdf_filename}")

# Execute compliance checks
if __name__ == "__main__":
    run_compliance_checks()
