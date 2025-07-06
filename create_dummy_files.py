import random
import re
import paramiko
import os

def get_ssh_connection(hostname):
    inventory_path = os.path.join(os.path.dirname(__file__), 'inventory.ini')
    ansible_host = None
    is_local_connection = False

    with open(inventory_path, 'r') as f:
        for line in f:
            if line.strip().startswith(hostname):
                if 'ansible_connection=local' in line:
                    is_local_connection = True
                    break
                else:
                    match = re.search(r'ansible_host=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', line)
                    if match:
                        ansible_host = match.group(1)
                        break
    
    if is_local_connection:
        return 'local', None

    if not ansible_host:
        raise Exception(f"Could not find host {hostname} or its IP in inventory.")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ansible_host, username="keith", key_filename=os.path.expanduser("~/.ssh/id_rsa"), timeout=10)
    return ssh, ansible_host

def create_dummy_files():
    inventory_path = os.path.join(os.path.dirname(__file__), 'inventory.ini')
    hosts = set()
    try:
        with open(inventory_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('[') and 'ansible_host' in line:
                    hostname = line.split(' ')[0]
                    hosts.add(hostname)
        hosts_list = sorted(list(hosts))
    except FileNotFoundError:
        print("Inventory file not found.")
        return

    # Select 3 random hosts
    random_hosts = random.sample(hosts_list, 3)

    for host in random_hosts:
        try:
            ssh, _ = get_ssh_connection(host)
            if ssh == 'local':
                os.system('sudo touch /var/run/reboot-required')
                os.system('sudo touch /var/cache/apt/archives/dummy-security-patch.deb')
            else:
                ssh.exec_command('sudo touch /var/run/reboot-required')
                ssh.exec_command('sudo touch /var/cache/apt/archives/dummy-security-patch.deb')
                ssh.close()
            print(f"Created dummy files on {host}")
        except Exception as e:
            print(f"Could not connect to {host}: {e}")

if __name__ == '__main__':
    create_dummy_files()
