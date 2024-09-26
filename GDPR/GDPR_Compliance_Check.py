import importlib
import json
import re
import paramiko
import logging
from subprocess import call
from dotenv import load_dotenv
import os
from datetime import datetime
import mysql.connector
from mysql.connector import Error

# Set up logging
logging.basicConfig(filename='GDPR_LOG.log', 
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def check_install_dependency(module_name):
    try:
        importlib.import_module(module_name)
    except ImportError:
        logging.info(f"{module_name} not found. Installing...")
        print(f"{module_name} not found. Installing...")
        call(["pip", "install", module_name])

check_install_dependency("paramiko")
check_install_dependency("mysql-connector-python")

# Load environment variables from .env file
load_dotenv()

# Retrieve credentials from environment variables
hostname = os.getenv('SSH_HOSTNAME')
username = os.getenv('SSH_USERNAME')
password = os.getenv('SSH_PASSWORD')
db_host = hostname  # MySQL database host
db_user = os.getenv('DB_USER')  # MySQL username
db_password = os.getenv('DB_PASSWORD')  # MySQL password
db_name = os.getenv('DB_NAME')  # MySQL database name

def create_ssh_client(hostname, username, password):
    """
    Creates and returns an SSH client connected to the remote host using password authentication.
    """
    print(f"Connecting to SSH server at {hostname} with user {username}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(hostname, username=username, password=password)
        logging.info("SSH connection established using password authentication.")
        print("SSH connection established.")
        return ssh
    except paramiko.AuthenticationException as e:
        logging.error(f"Authentication failed: {e}")
        print(f"Authentication failed: {e}")
        raise
    except Exception as e:
        logging.error(f"Error establishing SSH connection: {e}")
        print(f"Error establishing SSH connection: {e}")
        raise

def run_command(ssh_client, command):
    """
    Executes a command on the remote SSH client and returns the output.
    """
    print(f"Running command: {command}")
    stdin, stdout, stderr = ssh_client.exec_command(command)
    return stdout.read().decode()

def log_data_access(db_user_id, accessed_by, vendor, query, allowed_access):
    """
    Logs each data access attempt.
    """
    try:
        connection = mysql.connector.connect(
            host=hostname,
            port=3306,
            user=db_user,
            password=db_password,
            database=db_name
        )
        cursor = connection.cursor()

        # Insert into audit log
        log_query = """
        INSERT INTO audit_log (user_id, accessed_data, accessed_by, vendor, access_time, allowed_access)
        VALUES (%s, %s, %s, %s, %s, %s);
        """
        access_time = datetime.now()
        cursor.execute(log_query, (db_user_id, query, accessed_by, vendor, access_time, allowed_access))
        connection.commit()

        logging.info(f"Audit log created for user ID {db_user_id} accessed by {accessed_by} from vendor {vendor} with query: {query}")

    except Error as e:
        logging.error(f"Failed to create audit log: {e}")
        print(f"Failed to create audit log: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def check_user_consent_and_execute_query(db_user_id, vendor, query):
    """
    Intercept the query, check user consent, and then execute the query only if the user has granted consent to the vendor.
    """
    try:
        # Establish a connection to the MySQL database
        connection = mysql.connector.connect(
            host=hostname,
            port=3306,
            user=db_user,
            password=db_password,
            database=db_name
        )
        cursor = connection.cursor(dictionary=True)

        # Query to check user consent and allowed vendors
        consent_query = """
        SELECT consent_third_party_sharing, allowed_vendors 
        FROM users WHERE user_id = %s;
        """
        cursor.execute(consent_query, (db_user_id,))
        user = cursor.fetchone()

        if user:
            consent = user['consent_third_party_sharing']
            allowed_vendors = user['allowed_vendors'].split(',') if user['allowed_vendors'] else []

            # Check if vendor is allowed
            if vendor in allowed_vendors and consent:
                logging.info(f"Vendor {vendor} is allowed to access user ID {db_user_id}'s data.")

                # Execute the original query since the user has consented and vendor is allowed
                cursor.execute(query)
                result = cursor.fetchall()

                # Log the data access
                log_data_access(db_user_id, 'SystemAdmin', vendor, query, allowed_access=True)

                return result

            else:
                logging.warning(f"Access denied: Vendor {vendor} is NOT allowed to access user ID {db_user_id}'s data or consent not granted.")
                log_data_access(db_user_id, 'SystemAdmin', vendor, query, allowed_access=False)

                # Deny access
                raise PermissionError(f"Access denied: Vendor {vendor} is NOT allowed to access data for user ID {db_user_id}.")
        else:
            logging.error(f"User with ID {db_user_id} not found.")
            print(f"User with ID {db_user_id} not found.")
            return None

    except Error as e:
        logging.error(f"MySQL error: {e}")
        print(f"MySQL error: {e}")
        raise

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            logging.info("MySQL connection closed after query execution.")

if __name__ == "__main__":
    try:
        print("Starting GDPR-compliant query monitoring...")
        # Example usage: Vendor trying to access user data
        user_id = 1
        vendor = 'vendor1'
        query = "SELECT first_name, last_name FROM users WHERE user_id = 1;"

        # Intercept the query and check user consent before execution
        result = check_user_consent_and_execute_query(user_id, vendor, query)
        if result:
            print(f"Query executed successfully: {result}")
        else:
            print("Query execution failed due to non-compliance.")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}")
def generate_compliance_report():
    """
    Generate a report of all users who have not provided consent for third-party data sharing.
    """
    try:
        connection = mysql.connector.connect(
            host=db_host,
            port=3306,
            user=db_user,
            password=db_password,
            database=db_name
        )
        cursor = connection.cursor(dictionary=True)
        
        # Query to list all non-compliant users
        query = """
        SELECT user_id, first_name, last_name 
        FROM users WHERE consent_third_party_sharing = 0;
        """
        cursor.execute(query)
        non_compliant_users = cursor.fetchall()

        if non_compliant_users:
            logging.info(f"Non-compliant users found: {len(non_compliant_users)}")
            for user in non_compliant_users:
                print(f"User {user['first_name']} {user['last_name']} has not provided consent.")
                logging.info(f"User {user['first_name']} {user['last_name']} non-compliant.")
        else:
            logging.info("All users are compliant.")
            print("All users are compliant.")
    
    except Error as e:
        logging.error(f"Failed to generate compliance report: {e}")
        print(f"Failed to generate compliance report: {e}")
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            logging.info("MySQL connection closed after report generation.")
            print("MySQL connection closed after report generation.")

if __name__ == "__main__":
    try:
        print("Starting SSH and MySQL check process...")
        ssh = create_ssh_client(hostname, username, password)
        result = check_user_consent_status(ssh, 1)
        if result:
            print("Consent check passed.")
        else:
            print("Consent check failed.")
        # Generate a compliance report
        generate_compliance_report()
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}")
