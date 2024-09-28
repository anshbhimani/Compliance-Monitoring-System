import paramiko
import os
import logging
from mysql.connector import connect, Error
from dotenv import load_dotenv
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# Set up logging
logging.basicConfig(filename='gdpr_compliance_log.log',
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
    description = "Ensure that the system can connect to the MySQL database where user data is stored."
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

# Check 3: Verify existence of privacy policy
def check_privacy_policy(ssh_client):
    description = "Verify that the privacy policy exists and is accessible to users."
    remedy = "Ensure that the privacy policy is uploaded to the server and placed in the correct directory. Check permissions to make it accessible."
    try:
        result = run_remote_command(ssh_client, 'cat /path/to/privacy_policy.txt')  # Update path
        if "Privacy Policy" in result:
            logging.info("Privacy policy found.")
            return "Privacy policy", description, "Passed", ""
        else:
            failure_reason = "Privacy policy not found."
            logging.warning(failure_reason)
            return "Privacy policy", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check privacy policy: {e}"
        logging.error(failure_reason)
        return "Privacy policy", description, "Failed", remedy

# Check 4: Verify user consent management
def check_user_consent():
    description = "Ensure that user consent for data processing is recorded and managed in the system."
    remedy = "Implement user consent tracking in the database. Store records for user consent, especially for third-party sharing."
    try:
        query = "SELECT consent_third_party_sharing FROM users;"
        connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        connection.close()

        if result:
            logging.info("User consent management found.")
            return "User consent management", description, "Passed", ""
        else:
            failure_reason = "No user consent management found."
            logging.warning(failure_reason)
            return "User consent management", description, "Failed", remedy
    except Error as e:
        failure_reason = f"MySQL error during user consent check: {e}"
        logging.error(failure_reason)
        return "User consent management", description, "Failed", remedy

# Check 5: Verify encryption settings
def check_encryption(ssh_client):
    description = "Ensure that MySQL database encryption (SSL) is enabled."
    remedy = "Configure SSL encryption for MySQL. Ensure the 'my.cnf' file has SSL enabled."
    try:
        result = run_remote_command(ssh_client, 'grep -i "SSL" /etc/mysql/my.cnf')  # Change path if necessary
        if "SSL" in result:
            logging.info("MySQL SSL encryption is enabled.")
            return "MySQL encryption", description, "Passed", ""
        else:
            failure_reason = "MySQL SSL encryption not enabled."
            logging.warning(failure_reason)
            return "MySQL encryption", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check encryption settings: {e}"
        logging.error(failure_reason)
        return "MySQL encryption", description, "Failed", remedy

# Additional GDPR checks
# Check 6: Verify data retention policy is in place
def check_data_retention_policy(ssh_client):
    description = "Verify that a data retention policy is in place, ensuring data is stored for only as long as necessary."
    remedy = "Create a data retention policy document and upload it to the server. Ensure users are informed of how long their data is retained."
    try:
        result = run_remote_command(ssh_client, 'cat /path/to/data_retention_policy.txt')  # Update path
        if "Retention Period" in result:
            logging.info("Data retention policy found.")
            return "Data retention policy", description, "Passed", ""
        else:
            failure_reason = "Data retention policy not found."
            logging.warning(failure_reason)
            return "Data retention policy", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check data retention policy: {e}"
        logging.error(failure_reason)
        return "Data retention policy", description, "Failed", remedy

# Check 7: Verify data breach detection policy
def check_data_breach_policy(ssh_client):
    description = "Ensure that a data breach detection and notification policy is in place."
    remedy = "Develop a data breach response plan, including detection mechanisms and notification procedures, and store it on the server."
    try:
        result = run_remote_command(ssh_client, 'cat /path/to/data_breach_policy.txt')  # Update path
        if "Data Breach" in result:
            logging.info("Data breach policy found.")
            return "Data breach policy", description, "Passed", ""
        else:
            failure_reason = "Data breach policy not found."
            logging.warning(failure_reason)
            return "Data breach policy", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check data breach policy: {e}"
        logging.error(failure_reason)
        return "Data breach policy", description, "Failed", remedy

# Check 8: Verify user right to access data
def check_user_right_to_access():
    description = "Ensure users can access their data stored in the system, in compliance with GDPR."
    remedy = "Implement a user access request feature that allows users to retrieve a copy of their stored data."
    try:
        query = "SELECT first_name, last_name FROM users WHERE user_id = 1;"  # Example query
        connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        connection.close()

        if result:
            logging.info("Right to access check passed.")
            return "Right to access", description, "Passed", ""
        else:
            failure_reason = "Right to access check failed."
            logging.warning(failure_reason)
            return "Right to access", description, "Failed", remedy
    except Error as e:
        failure_reason = f"MySQL error during right to access check: {e}"
        logging.error(failure_reason)
        return "Right to access", description, "Failed", remedy

# Check 9: Verify user right to erasure (right to be forgotten)
def check_user_right_to_erasure():
    description = "Ensure users have the ability to request the erasure of their data (Right to be forgotten)."
    remedy = "Implement functionality for users to request the deletion of their data, and ensure this is processed promptly."
    try:
        query = "SELECT user_id FROM users WHERE user_id = 1;"  # Example query for deletion
        connection = connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        connection.close()

        if result:
            logging.info("Right to erasure check passed.")
            return "Right to erasure", description, "Passed", ""
        else:
            failure_reason = "Right to erasure check failed."
            logging.warning(failure_reason)
            return "Right to erasure", description, "Failed", remedy
    except Error as e:
        failure_reason = f"MySQL error during right to erasure check: {e}"
        logging.error(failure_reason)
        return "Right to erasure", description, "Failed", remedy

# Check 10: Verify third-party vendor contracts
def check_vendor_contracts(ssh_client):
    description = "Ensure contracts with third-party vendors are in place and GDPR-compliant."
    remedy = "Obtain GDPR-compliant contracts from third-party vendors who process personal data."
    try:
        result = run_remote_command(ssh_client, 'cat /path/to/vendor_contracts.txt')  # Update path
        if "Vendor Agreement" in result:
            logging.info("Vendor contracts found.")
            return "Third-party vendor contracts", description, "Passed", ""
        else:
            failure_reason = "Vendor contracts not found."
            logging.warning(failure_reason)
            return "Third-party vendor contracts", description, "Failed", remedy
    except Exception as e:
        failure_reason = f"Failed to check third-party vendor contracts: {e}"
        logging.error(failure_reason)
        return "Third-party vendor contracts", description, "Failed", remedy

# Generate PDF report with improved formatting
def generate_pdf_report(checks):
    pdf_filename = "GDPR_Compliance_Report.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']

    # Add Title
    elements.append(Paragraph("GDPR Compliance Report", title_style))
    elements.append(Spacer(1, 0.5 * inch))

    # Add Header for the table section
    elements.append(Paragraph("Compliance Check Results", heading_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Create table data with proper headers
    table_data = [["Check", "Description", "Result", "Remedy (if failed)"]]

    # Append each check's details (name, description, result, and remedy)
    for check in checks:
        check_name = Paragraph(check[0], normal_style)
        description = Paragraph(check[1], normal_style)
        result = Paragraph(check[2], normal_style)
        remedy = Paragraph(check[3], normal_style) if check[2] == "Failed" else Paragraph("", normal_style)
        
        # Add the check details row to table data
        table_data.append([check_name, description, result, remedy])

    # Create table with formatting and styling
    table = Table(table_data, colWidths=[2.5 * inch, 4 * inch, 1 * inch, 4 * inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 1), (-1, -1), 'TOP'),
        ('ALIGN', (2, 1), (2, -1), 'CENTER'),  # Center align for result column
    ]))

    elements.append(table)
    
    # Build the PDF
    doc.build(elements)
    logging.info(f"PDF report generated: {pdf_filename}")
    
# Main function
def main():
    try:
        ssh_client = create_ssh_client(SSH_HOSTNAME, SSH_USERNAME, SSH_PASSWORD)
        checks = []

        # Perform compliance checks
        checks.append(check_ssh_connection(ssh_client))
        checks.append(check_mysql_connection())
        checks.append(check_privacy_policy(ssh_client))
        checks.append(check_user_consent())
        checks.append(check_encryption(ssh_client))
        checks.append(check_data_retention_policy(ssh_client))
        checks.append(check_data_breach_policy(ssh_client))
        checks.append(check_user_right_to_access())
        checks.append(check_user_right_to_erasure())
        checks.append(check_vendor_contracts(ssh_client))

        # Generate PDF report
        generate_pdf_report(checks)

        ssh_client.close()
        logging.info("SSH connection closed.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
