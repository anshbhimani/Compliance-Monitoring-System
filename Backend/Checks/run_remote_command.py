import paramiko
import logging

logging.basicConfig(level=logging.INFO,filename='LogFile.log',filemode='a',format='%(asctime)s - %(levelname)s - File: %(filename)s , Line: %(lineno)d - %(message)s')

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