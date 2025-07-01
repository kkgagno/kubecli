import os
import yaml
import datetime
import helm
import json
import pytz
import re
import subprocess
import threading # Import threading
import uuid # Import uuid
from flask import Flask, render_template, Response, redirect, url_for, request, flash, session, send_from_directory, jsonify, make_response
import pdfkit
from bs4 import BeautifulSoup
import csv
from io import StringIO
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from kubernetes import client, config
import paramiko

app = Flask(__name__)
app.secret_key = os.urandom(24) # Required for flash messages

# Dictionary to store the status of long-running tasks
running_tasks = {}

# --- Configuration Variables ---
KUBECONFIG_PATH = os.environ.get("KUBECONFIG_PATH", os.path.expanduser("~/.kube/config"))
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", os.path.expanduser("~/.ssh/id_rsa"))
SSH_USERNAME = os.environ.get("SSH_USERNAME", "keith")
# -----------------------------

# Load Kubernetes configuration
try:
    config.load_kube_config(config_file=KUBECONFIG_PATH)
except config.ConfigException:
    # If running inside a cluster, use in-cluster config
    try:
        config.load_incluster_config()
    except config.ConfigException:
        raise Exception("Could not configure kubernetes client")

core_api = client.CoreV1Api()
apps_api = client.AppsV1Api()
batch_api = client.BatchV1Api()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

import logging

logging.basicConfig(filename=os.path.join(os.path.expanduser('~'), 'ansible_playbook.log'), level=logging.INFO)

def run_ansible_playbook_async(task_id, task_type, playbook_path, inventory_path, extra_vars=None, limit=None):
    running_tasks[task_id] = {'status': 'running', 'output': '', 'type': task_type}
    command = [
        os.path.expanduser('~/simple_kube_web_app/venv/bin/ansible-playbook'),
        '-i', inventory_path,
        '--user', SSH_USERNAME,
        '--private-key', SSH_KEY_PATH,
        '--extra-vars', 'ansible_ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"',
        '--extra-vars', 'ansible_python_interpreter=/usr/bin/python3'
    ]
    if limit:
        command.extend(['--limit', limit])
    if extra_vars:
        for key, value in extra_vars.items():
            command.extend(['--extra-vars', f'{key}={value}'])
    command.append(playbook_path)

    with open(os.path.join(os.path.expanduser('~'), "simple_kube_web_app/ansible_command.log"), "w") as f:
        f.write(f"Executing Ansible command: {' '.join(command)}\n")

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        output = process.stdout + process.stderr
        with open(os.path.join(os.path.expanduser('~'), "simple_kube_web_app/ansible_command.log"), "a") as f:
            f.write(f"Ansible playbook output:\n{output}\n")
        if process.returncode == 0:
            running_tasks[task_id]['status'] = 'completed'
            running_tasks[task_id]['output'] = output
        else:
            running_tasks[task_id]['status'] = 'failed'
            running_tasks[task_id]['output'] = f"Playbook failed with exit code {process.returncode}.\n{output}"
    except Exception as e:
        running_tasks[task_id]['status'] = 'error'
        running_tasks[task_id]['output'] = f"An error occurred: {e}"
        with open(os.path.join(os.path.expanduser('~'), "simple_kube_web_app/ansible_command.log"), "a") as f:
            f.write(f"An error occurred: {e}\n")


import socket

@app.route('/run_goss_playbook', methods=['POST'])
def run_goss_playbook():
    for task_id, task_info in running_tasks.items():
        if task_info.get('type') == 'goss' and task_info.get('status') == 'running':
            return jsonify({'message': 'GOSS playbook is already running.'}), 409

    task_id = str(uuid.uuid4())
    playbook_path = os.path.join(os.path.dirname(__file__), 'ansible_goss_compliance', 'playbook.yml')
    
    try:
        nodes = core_api.list_node()
        inventory_content = ""
        local_hostname = socket.gethostname()
        for node in nodes.items:
            if node.metadata.name == local_hostname:
                continue  # Skip the local host
            for address in node.status.addresses:
                if address.type == "InternalIP":
                    inventory_content += f"{node.metadata.name} ansible_host={address.address}\n"
        
        inventory_path = "/tmp/goss_inventory.ini"
        with open(inventory_path, "w") as f:
            f.write(inventory_content)

    except Exception as e:
        return jsonify({'message': f'Error creating inventory: {e}'}), 500

    thread = threading.Thread(target=run_ansible_playbook_async, args=(task_id, 'goss', playbook_path, inventory_path, {'goss_vars_file': os.path.join(os.path.dirname(__file__), 'ansible_goss_compliance', 'goss-vars.yml')}))
    thread.start()
    return jsonify({'task_id': task_id, 'message': 'GOSS playbook started.'}), 202


@app.route('/run_report_playbook', methods=['POST'])
def run_report_playbook():
    for task_id, task_info in running_tasks.items():
        if task_info.get('type') == 'report' and task_info.get('status') == 'running':
            return jsonify({'message': 'Compliance report generation is already running.'}), 409

    task_id = str(uuid.uuid4())
    playbook_path = os.path.join(os.path.dirname(__file__), 'ansible_goss_compliance', 'report_playbook.yml')
    
    inventory_path = f"/tmp/report_inventory_{task_id}.ini"
    with open(inventory_path, "w") as f:
        f.write("localhost ansible_connection=local\n")

    # Move old reports to archive
    reports_dir = os.path.join(os.path.dirname(__file__), 'ansible_goss_compliance', 'compliance_html_reports')
    archive_dir = os.path.join(os.path.dirname(__file__), 'ansible_goss_compliance', 'compliance_html_reports_archive')
    now = datetime.datetime.now()
    
    if not os.path.exists(archive_dir):
        os.makedirs(archive_dir)

    for filename in os.listdir(reports_dir):
        if filename.endswith('.html'):
            report_path = os.path.join(reports_dir, filename)
            archive_path = os.path.join(archive_dir, f"{now.strftime('%Y-%m-%d_%H-%M-%S')}_{filename}")
            os.rename(report_path, archive_path)

    # Enforce retention policy
    for filename in os.listdir(archive_dir):
        archive_path = os.path.join(archive_dir, filename)
        try:
            file_time_str = filename.split('_')[0]
            file_time = datetime.datetime.strptime(file_time_str, '%Y-%m-%d')
            if (now - file_time).days > 10:
                os.remove(archive_path)
        except (ValueError, IndexError):
            # Handle files that don't match the expected naming convention
            pass

    thread = threading.Thread(target=run_ansible_playbook_async, args=(task_id, 'report', playbook_path, inventory_path, {'goss_report_dir': '/tmp/goss_reports'}))
    thread.start()
    return jsonify({'task_id': task_id, 'message': 'Compliance report generation started.'}), 202


@app.route('/get_task_status/<task_id>')
def get_task_status(task_id):
    task = running_tasks.get(task_id)
    if task:
        return jsonify(task)
    return jsonify({'status': 'not_found', 'message': 'Task not found.'}), 404

@app.route('/get_all_task_statuses')
def get_all_task_statuses():
    return jsonify(running_tasks)

@app.route('/playbook_output/<task_id>')
def playbook_output(task_id):
    task = running_tasks.get(task_id)
    if task:
        return render_template('playbook_output.html', task=task)
    return "Task not found or output not available.", 404

@app.route('/login', methods=['GET', 'POST'])

def login():
    if request.method == 'POST':
        username = request.form['username']
        entered_password = request.form['password']
        
        stored_password_hash = None
        try:
            with open('password.txt', 'r') as f:
                stored_password_hash = f.read().strip()
        except FileNotFoundError:
            pass  # No password file, assume default blank password

        if username == 'admin':
            if stored_password_hash:
                # Password file exists, check against hash
                if check_password_hash(stored_password_hash, entered_password):
                    session['logged_in'] = True
                    return redirect(url_for('index'))
                else:
                    flash('Invalid credentials', 'error')
            else:
                # No password file, allow blank password
                if entered_password == '':
                    session['logged_in'] = True
                    return redirect(url_for('index'))
                else:
                    flash('Invalid credentials', 'error')
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password == confirm_password:
            with open('password.txt', 'w') as f:
                f.write(generate_password_hash(new_password))
            flash('Password changed successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Passwords do not match.', 'error')
    return render_template('change_password.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return redirect(url_for('get_pods'))

@app.route('/pods')
@login_required
def get_pods():
    search_query = request.args.get('search')
    selected_node_name = request.args.get('node_name', 'all') # Default to 'all'
    selected_namespace = request.args.get('namespace', 'all') # Default to 'all'

    try:
        # Fetch all namespaces for the dropdown
        namespaces_obj = core_api.list_namespace(watch=False)
        namespaces = sorted([ns.metadata.name for ns in namespaces_obj.items])
        namespaces.insert(0, 'all') # Add 'all' option at the beginning

        # Fetch all node names for the dropdown
        nodes_obj = core_api.list_node(watch=False)
        nodes_list = sorted([node.metadata.name for node in nodes_obj.items])

        if selected_namespace == 'all':
            pods = core_api.list_pod_for_all_namespaces(watch=False)
        else:
            pods = core_api.list_namespaced_pod(namespace=selected_namespace, watch=False)

        filtered_pods = []
        for pod in pods.items:
            # Apply search query filter
            if search_query and search_query.lower() not in pod.metadata.name.lower():
                continue
            # Apply node name filter
            if selected_node_name != 'all' and pod.spec.node_name != selected_node_name:
                continue
            filtered_pods.append(pod)

        # Calculate age for each pod
        for pod in filtered_pods:
            pod.age = calculate_age(pod.metadata.creation_timestamp)

        return render_template('pods.html', pods=filtered_pods, search_query=search_query, nodes_list=nodes_list, selected_node_name=selected_node_name, namespaces=namespaces, selected_namespace=selected_namespace)
    except Exception as e:
        flash(f"Error fetching pods: {e}", 'error')
        return render_template('pods.html', pods=[], search_query=search_query, nodes_list=[], selected_node_name='all', namespaces=['all'], selected_namespace='all')

def calculate_age(creation_timestamp):
    now = datetime.datetime.now(pytz.utc)
    age = now - creation_timestamp
    
    days = age.days
    seconds = age.seconds
    
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    
    if days > 0:
        return f"{days}d {hours}h"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    elif minutes > 0:
        return f"{minutes}m"
    else:
        return "0m"

@app.route('/logs/<namespace>/<pod_name>')
@login_required
def pod_logs(namespace, pod_name):
    container_name = request.args.get('container')
    try:
        if container_name:
            logs = core_api.read_namespaced_pod_log(name=pod_name, namespace=namespace, container=container_name)
        else:
            logs = core_api.read_namespaced_pod_log(name=pod_name, namespace=namespace)
        return Response(logs, mimetype='text/plain')
    except Exception as e:
        return f"Error fetching logs for pod {pod_name} in namespace {namespace}: {e}"

@app.route('/delete_pod/<namespace>/<pod_name>', methods=['POST'])
@login_required
def delete_pod(namespace, pod_name):
    try:
        core_api.delete_namespaced_pod(name=pod_name, namespace=namespace)
        flash(f"Pod {pod_name} in namespace {namespace} deleted successfully.", 'success')
    except Exception as e:
        flash(f"Error deleting pod {pod_name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_pods'))

@app.route('/describe/<resource_type>/<namespace>/<name>')
@login_required
def describe_resource(resource_type, namespace, name):
    try:
        if resource_type == 'pod':
            resource = core_api.read_namespaced_pod(name=name, namespace=namespace, _preload_content=False)
        elif resource_type == 'deployment':
            resource = apps_api.read_namespaced_deployment(name=name, namespace=namespace, _preload_content=False)
        elif resource_type == 'service':
            resource = core_api.read_namespaced_service(name=name, namespace=namespace, _preload_content=False)
        elif resource_type == 'node':
            resource = core_api.read_node(name=name, _preload_content=False)
        elif resource_type == 'persistentvolumeclaim':
            resource = core_api.read_namespaced_persistent_volume_claim(name=name, namespace=namespace, _preload_content=False)
        elif resource_type == 'configmap':
            resource = core_api.read_namespaced_config_map(name=name, namespace=namespace, _preload_content=False)
        elif resource_type == 'statefulset':
            resource = apps_api.read_namespaced_stateful_set(name=name, namespace=namespace, _preload_content=False)
        elif resource_type == 'daemonset':
            resource = apps_api.read_namespaced_daemon_set(name=name, namespace=namespace, _preload_content=False)
        elif resource_type == 'job':
            resource = batch_api.read_namespaced_job(name=name, namespace=namespace, _preload_content=False)
        elif resource_type == 'secret':
            resource = core_api.read_namespaced_secret(name=name, namespace=namespace, _preload_content=False)
        else:
            return f"Unknown resource type: {resource_type}"

        return render_template('describe.html', resource_yaml=yaml.dump(yaml.safe_load(resource.data)))

    except Exception as e:
        return f"Error describing resource: {e}"

@app.route('/deployments')
@login_required
def get_deployments():
    search_query = request.args.get('search')
    try:
        deployments = apps_api.list_deployment_for_all_namespaces(watch=False)
        if search_query:
            deployments.items = [dep for dep in deployments.items if search_query.lower() in dep.metadata.name.lower()]
        return render_template('deployments.html', deployments=deployments.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching deployments: {e}", 'error')
        return render_template('deployments.html', deployments=[], search_query=search_query)

@app.route('/rollout_restart_deployment/<namespace>/<name>', methods=['POST'])
@login_required
def rollout_restart_deployment(namespace, name):
    try:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": now
                        }
                    }
                }
            }
        }
        apps_api.patch_namespaced_deployment(name=name, namespace=namespace, body=body)
        flash(f"Deployment {name} in namespace {namespace} restarted successfully.", 'success')
    except Exception as e:
        flash(f"Error restarting deployment {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_deployments'))

@app.route('/delete_deployment/<namespace>/<name>', methods=['POST'])
@login_required
def delete_deployment(namespace, name):
    try:
        apps_api.delete_namespaced_deployment(name=name, namespace=namespace)
        flash(f"Deployment {name} in namespace {namespace} deleted successfully.", 'success')
    except Exception as e:
        flash(f"Error deleting deployment {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_deployments'))


@app.route('/delete_service/<namespace>/<name>', methods=['POST'])
@login_required
def delete_service(namespace, name):
    try:
        core_api.delete_namespaced_service(name=name, namespace=namespace)
        flash(f"Service {name} in namespace {namespace} deleted successfully.", 'success')
    except Exception as e:
        flash(f"Error deleting service {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_services'))


@app.route('/services')
@login_required
def get_services():
    search_query = request.args.get('search')
    try:
        services = core_api.list_service_for_all_namespaces(watch=False)
        if search_query:
            services.items = [svc for svc in services.items if search_query.lower() in svc.metadata.name.lower()]
        return render_template('services.html', services=services.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching services: {e}", 'error')
        return render_template('services.html', services=[], search_query=search_query)

@app.route('/cordon_node/<node_name>', methods=['POST'])
@login_required
def cordon_node(node_name):
    policy_api = client.PolicyV1Api()
    try:
        # Cordon the node
        body = {
            "spec": {
                "unschedulable": True
            }
        }
        core_api.patch_node(name=node_name, body=body)
        flash(f"Node {node_name} cordoned successfully.", 'success')

        # Evict pods from the node
        pods = core_api.list_pod_for_all_namespaces(field_selector=f'spec.nodeName=={node_name}')
        evicted_count = 0
        for pod in pods.items:
            # Skip DaemonSet pods
            if pod.metadata.owner_references and any(
                owner.kind == "DaemonSet" for owner in pod.metadata.owner_references
            ):
                print(f"Skipping DaemonSet pod: {pod.metadata.name}")
                continue

            eviction_body = client.V1Eviction(
                metadata=client.V1ObjectMeta(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace
                )
            )
            try:
                core_api.create_namespaced_pod_eviction(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    body=eviction_body
                )
                evicted_count += 1
                print(f"Evicted pod: {pod.metadata.name} from namespace: {pod.metadata.namespace}")
            except client.ApiException as e:
                print(f"Error evicting pod {pod.metadata.name}: {e}")
                flash(f"Error evicting pod {pod.metadata.name}: {e}", 'error')
        
        if evicted_count > 0:
            flash(f"Successfully evicted {evicted_count} pods from node {node_name}.", 'success')
        else:
            flash(f"No non-DaemonSet pods to evict from node {node_name}.", 'info')

    except Exception as e:
        flash(f"Error draining node {node_name}: {e}", 'error')
    return redirect(url_for('get_nodes'))

@app.route('/uncordon_node/<node_name>', methods=['POST'])
@login_required
def uncordon_node(node_name):
    try:
        body = {
            "spec": {
                "unschedulable": False
            }
        }
        core_api.patch_node(name=node_name, body=body)
        flash(f"Node {node_name} uncordoned successfully.", 'success')
    except Exception as e:
        flash(f"Error uncordoning node {node_name}: {e}", 'error')
    return redirect(url_for('get_nodes'))

@app.route('/reboot_node/<node_name>', methods=['POST'])
@login_required
def reboot_node(node_name):
    try:
        node = core_api.read_node(name=node_name)
        node_ip = None
        for address in node.status.addresses:
            if address.type == 'InternalIP':
                node_ip = address.address
                break
        
        if not node_ip:
            flash(f"Could not get internal IP for node {node_name}", 'error')
            return redirect(url_for('get_nodes'))

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(node_ip, username=SSH_USERNAME, key_filename=SSH_KEY_PATH)
        stdin, stdout, stderr = ssh.exec_command('sudo shutdown -r now')
        stdout.channel.recv_exit_status()
        ssh.close()
        flash(f"Reboot command issued for node {node_name}.", 'success')
    except Exception as e:
        flash(f"Error rebooting node {node_name}: {e}", 'error')
    return redirect(url_for('get_nodes'))

@app.route('/check_reboot_required/<node_name>')
@login_required
def check_reboot_required(node_name):
    try:
        node = core_api.read_node(name=node_name)
        node_ip = None
        for address in node.status.addresses:
            if address.type == 'InternalIP':
                node_ip = address.address
                break
        
        if not node_ip:
            flash(f"Could not get internal IP for node {node_name}", 'error')
            return redirect(url_for('get_nodes'))

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(node_ip, username=SSH_USERNAME, key_filename=SSH_KEY_PATH)
        stdin, stdout, stderr = ssh.exec_command('if [ -f /var/run/reboot-required ]; then echo "reboot required"; fi')
        reboot_status = stdout.read().decode('utf-8').strip()
        ssh.close()

        if reboot_status == "reboot required":
            flash(f"Node {node_name} requires a reboot.", 'warning')
        else:
            flash(f"Node {node_name} does not require a reboot.", 'success')
    except Exception as e:
        flash(f"Error checking reboot status for node {node_name}: {e}", 'error')
    return redirect(url_for('get_nodes'))

@app.route('/get_last_reboot_time/<node_name>')
@login_required
def get_last_reboot_time(node_name):
    try:
        node = core_api.read_node(name=node_name)
        node_ip = None
        for address in node.status.addresses:
            if address.type == 'InternalIP':
                node_ip = address.address
                break
        
        if not node_ip:
            flash(f"Could not get internal IP for node {node_name}", 'error')
            return redirect(url_for('get_nodes'))

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(node_ip, username=SSH_USERNAME, key_filename=SSH_KEY_PATH)
        stdin, stdout, stderr = ssh.exec_command('uptime -s')
        last_reboot_time = stdout.read().decode('utf-8').strip()
        ssh.close()
        flash(f"Last reboot time for node {node_name}: {last_reboot_time}", 'info')
    except Exception as e:
        flash(f"Error getting last reboot time for node {node_name}: {e}", 'error')
    return redirect(url_for('get_nodes'))

@app.route('/nodes')
@login_required
def get_nodes():
    search_query = request.args.get('search')
    try:
        nodes = core_api.list_node(watch=False)
        if search_query:
            nodes.items = [node for node in nodes.items if search_query.lower() in node.metadata.name.lower()]

        for node in nodes.items:
            node.reboot_required = False
            node.hours_since_reboot = "N/A"
            node.status_display = "Unknown" # Initialize status display
            node.hours_since_reboot = "N/A" # Initialize hours since reboot

            # Determine node status (Ready/NotReady, SchedulingDisabled)
            if node.status and node.status.conditions:
                ready_status = "Unknown"
                for condition in node.status.conditions:
                    if condition.type == "Ready":
                        if condition.status == "True":
                            ready_status = "Ready"
                        else:
                            ready_status = "NotReady"
                        break
                
                if node.spec and node.spec.unschedulable:
                    if ready_status == "Ready":
                        node.status_display = "Ready,SchedulingDisabled"
                    else:
                        node.status_display = f"{ready_status},SchedulingDisabled"
                else:
                    node.status_display = ready_status

            try:
                node_ip = None
                for address in node.status.addresses:
                    if address.type == 'InternalIP':
                        node_ip = address.address
                        break
                
                if not node_ip:
                    continue

                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(node_ip, username=SSH_USERNAME, key_filename=SSH_KEY_PATH)
                
                # Check for reboot required file
                stdin, stdout, stderr = ssh.exec_command('if [ -f /var/run/reboot-required ]; then echo "reboot required"; fi')
                reboot_status = stdout.read().decode('utf-8').strip()
                if reboot_status == "reboot required":
                    node.reboot_required = True

                # Get last reboot time
                stdin, stdout, stderr = ssh.exec_command('uptime -s')
                last_reboot_time_str = stdout.read().decode('utf-8').strip()
                if last_reboot_time_str:
                    last_reboot_time = datetime.datetime.strptime(last_reboot_time_str, '%Y-%m-%d %H:%M:%S')
                    now = datetime.datetime.now()
                    minutes_since_reboot = (now - last_reboot_time).total_seconds() / 60
                    node.minutes_since_reboot = minutes_since_reboot

                ssh.close()

            except Exception as e:
                print(f"Could not check reboot status for node {node.metadata.name}: {e}")


        return render_template('nodes.html', nodes=nodes.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching nodes: {e}", 'error')
        return render_template('nodes.html', nodes=[], search_query=search_query)

@app.route('/persistentvolumeclaims')
@login_required
def get_persistentvolumeclaims():
    search_query = request.args.get('search')
    try:
        pvcs = core_api.list_persistent_volume_claim_for_all_namespaces(watch=False)
        if search_query:
            pvcs.items = [pvc for pvc in pvcs.items if search_query.lower() in pvc.metadata.name.lower()]
        return render_template('persistentvolumeclaims.html', pvcs=pvcs.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching persistent volume claims: {e}", 'error')
        return render_template('persistentvolumeclaims.html', pvcs=[], search_query=search_query)

@app.route('/delete_pvc/<namespace>/<name>', methods=['POST'])
@login_required
def delete_pvc(namespace, name):
    try:
        core_api.delete_namespaced_persistent_volume_claim(name=name, namespace=namespace)
        flash(f"Persistent Volume Claim {name} in namespace {namespace} deleted successfully.", 'success')
    except Exception as e:
        flash(f"Error deleting Persistent Volume Claim {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_persistentvolumeclaims'))

@app.route('/configmaps')
@login_required
def get_configmaps():
    search_query = request.args.get('search')
    try:
        configmaps = core_api.list_config_map_for_all_namespaces(watch=False)
        if search_query:
            configmaps.items = [cm for cm in configmaps.items if search_query.lower() in cm.metadata.name.lower()]
        return render_template('configmaps.html', configmaps=configmaps.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching configmaps: {e}", 'error')
        return render_template('configmaps.html', configmaps=[], search_query=search_query)

@app.route('/configmap_data/<namespace>/<name>')
@login_required
def configmap_data(namespace, name):
    try:
        configmap = core_api.read_namespaced_config_map(name=name, namespace=namespace)
        return render_template('configmap_data.html', configmap_data=configmap.data, name=name, namespace=namespace)
    except Exception as e:
        return f"Error fetching ConfigMap data: {e}"

@app.route('/statefulsets')
@login_required
def get_statefulsets():
    search_query = request.args.get('search')
    try:
        statefulsets = apps_api.list_stateful_set_for_all_namespaces(watch=False)
        if search_query:
            statefulsets.items = [ss for ss in statefulsets.items if search_query.lower() in ss.metadata.name.lower()]
        return render_template('statefulsets.html', statefulsets=statefulsets.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching statefulsets: {e}", 'error')
        return render_template('statefulsets.html', statefulsets=[], search_query=search_query)

@app.route('/rollout_restart_statefulset/<namespace>/<name>', methods=['POST'])
@login_required
def rollout_restart_statefulset(namespace, name):
    try:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": now
                        }
                    }
                }
            }
        }
        apps_api.patch_namespaced_stateful_set(name=name, namespace=namespace, body=body)
        flash(f"StatefulSet {name} in namespace {namespace} restarted successfully.", 'success')
    except Exception as e:
        flash(f"Error restarting StatefulSet {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_statefulsets'))

@app.route('/delete_statefulset/<namespace>/<name>', methods=['POST'])
@login_required
def delete_statefulset(namespace, name):
    try:
        apps_api.delete_namespaced_stateful_set(name=name, namespace=namespace)
        flash(f"StatefulSet {name} in namespace {namespace} deleted successfully.", 'success')
    except Exception as e:
        flash(f"Error deleting StatefulSet {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_statefulsets'))

@app.route('/daemonsets')
@login_required
def get_daemonsets():
    search_query = request.args.get('search')
    try:
        daemonsets = apps_api.list_daemon_set_for_all_namespaces(watch=False)
        if search_query:
            daemonsets.items = [ds for ds in daemonsets.items if search_query.lower() in ds.metadata.name.lower()]
        return render_template('daemonsets.html', daemonsets=daemonsets.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching daemonsets: {e}", 'error')
        return render_template('daemonsets.html', daemonsets=[], search_query=search_query)

@app.route('/rollout_restart_daemonset/<namespace>/<name>', methods=['POST'])
@login_required
def rollout_restart_daemonset(namespace, name):
    try:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": now
                        }
                    }
                }
            }
        }
        apps_api.patch_namespaced_daemon_set(name=name, namespace=namespace, body=body)
        flash(f"DaemonSet {name} in namespace {namespace} restarted successfully.", 'success')
    except Exception as e:
        flash(f"Error restarting DaemonSet {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_daemonsets'))

@app.route('/delete_daemonset/<namespace>/<name>', methods=['POST'])
@login_required
def delete_daemonset(namespace, name):
    try:
        apps_api.delete_namespaced_daemon_set(name=name, namespace=namespace)
        flash(f"DaemonSet {name} in namespace {namespace} deleted successfully.", 'success')
    except Exception as e:
        flash(f"Error deleting DaemonSet {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_daemonsets'))

@app.route('/jobs')
@login_required
def get_jobs():
    search_query = request.args.get('search')
    try:
        jobs = batch_api.list_job_for_all_namespaces(watch=False)
        if search_query:
            jobs.items = [job for job in jobs.items if search_query.lower() in job.metadata.name.lower()]
        return render_template('jobs.html', jobs=jobs.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching jobs: {e}", 'error')
        return render_template('jobs.html', jobs=[], search_query=search_query)

@app.route('/secrets')
@login_required
def get_secrets():
    search_query = request.args.get('search')
    try:
        secrets = core_api.list_secret_for_all_namespaces(watch=False)
        if search_query:
            secrets.items = [secret for secret in secrets.items if search_query.lower() in secret.metadata.name.lower()]
        return render_template('secrets.html', secrets=secrets.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching secrets: {e}", 'error')
        return render_template('secrets.html', secrets=[], search_query=search_query)

@app.route('/events')
@login_required
def get_events():
    search_query = request.args.get('search')
    try:
        events = core_api.list_event_for_all_namespaces(watch=False)
        if search_query:
            events.items = [event for event in events.items if search_query.lower() in event.metadata.name.lower() or search_query.lower() in event.message.lower()]
        return render_template('events.html', events=events.items, search_query=search_query)
    except Exception as e:
        flash(f"Error fetching events: {e}", 'error')
        return render_template('events.html', events=[], search_query=search_query)

@app.route('/helm_charts')
@login_required
def get_helm_charts():
    search_query = request.args.get('search')
    helm_charts = []
    try:
        # Use subprocess to run the helm command directly
        print("Executing helm list command...")
        list_command = ['/usr/local/bin/helm', 'list', '--all-namespaces', '-o', 'json', '--kubeconfig', os.path.expanduser('~/.kube/config')]
        result = subprocess.run(
            list_command,
            capture_output=True,
            text=True,
            check=True
        )
        print(f"Helm list stdout: {result.stdout}")
        print(f"Helm list stderr: {result.stderr}")
        releases = json.loads(result.stdout)
        
        for release in releases:
            print(f"Fetching manifest for chart: {release['name']} in namespace: {release['namespace']}")
            try:
                manifest_command = ['/usr/local/bin/helm', 'get', 'manifest', release['name'], '--namespace', release['namespace'], '--kubeconfig', os.path.expanduser('~/.kube/config')]
                manifest_result = subprocess.run(
                    manifest_command,
                    capture_output=True,
                    text=True,
                    check=True
                )
                manifest = manifest_result.stdout
                print(f"Manifest for {release['name']} fetched successfully.")
                
                resources = []
                if manifest.strip(): # Check if manifest is not empty or just whitespace
                    try:
                        for doc in yaml.safe_load_all(manifest):
                            if doc and 'kind' in doc and 'metadata' in doc and 'name' in doc['metadata']:
                                resources.append({
                                    'kind': doc['kind'],
                                    'name': doc['metadata']['name']
                                })
                    except yaml.YAMLError as e:
                        print(f"Error parsing YAML for {release['name']}: {e}")
                        print(f"Problematic manifest content:\n{manifest}")
                        flash(f"Error parsing YAML for {release['name']}: {e}", 'warning')
                else:
                    print(f"Manifest for {release['name']} is empty.")
                    flash(f"Manifest for {release['name']} is empty.", 'info')
                helm_charts.append({
                    'name': release['name'],
                    'namespace': release['namespace'],
                    'chart': release['chart'],
                    'status': release['status'],
                    'resources': resources
                })
            except subprocess.CalledProcessError as e:
                print(f"Error fetching manifest for {release['name']}: {e}")
                print(f"Stderr for manifest command: {e.stderr}")
                flash(f"Error fetching manifest for {release['name']}: {e.stderr}", 'warning')
                # Continue to the next release even if one fails
            except yaml.YAMLError as e:
                print(f"Error parsing YAML for {release['name']}: {e}")
                flash(f"Error parsing YAML for {release['name']}: {e}", 'warning')
                # Continue to the next release even if YAML parsing fails
            except Exception as e:
                print(f"Unexpected error processing manifest for {release['name']}: {e}")
                flash(f"Unexpected error processing manifest for {release['name']}: {e}", 'warning')

        if search_query:
            helm_charts = [chart for chart in helm_charts if search_query.lower() in chart['name'].lower()]

        return render_template('helm_charts.html', helm_charts=helm_charts, search_query=search_query)
    except subprocess.CalledProcessError as e:
        print(f"Error executing helm list: {e}")
        print(f"Stderr from helm list: {e.stderr}")
        flash(f"Error fetching Helm charts: {e.stderr}", 'error')
        return render_template('helm_charts.html', helm_charts=[], search_query=search_query)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from helm list output: {e}")
        flash(f"Error decoding Helm list output: {e}", 'error')
        return render_template('helm_charts.html', helm_charts=[], search_query=search_query)
    except Exception as e:
        print(f"General error in get_helm_charts: {e}")
        flash(f"Error fetching Helm charts: {e}", 'error')
        return render_template('helm_charts.html', helm_charts=[], search_query=search_query)


@app.route('/delete_helm_chart/<namespace>/<name>', methods=['POST'])
@login_required
def delete_helm_chart(namespace, name):
    try:
        subprocess.run(
            ['/usr/local/bin/helm', 'uninstall', name, '--namespace', namespace, '--kubeconfig', os.path.expanduser('~/.kube/config')],
            capture_output=True,
            text=True,
            check=True
        )
        flash(f"Helm chart {name} in namespace {namespace} deleted successfully.", 'success')
    except Exception as e:
        flash(f"Error deleting helm chart {name} in namespace {namespace}: {e}", 'error')
    return redirect(url_for('get_helm_charts'))

@app.route('/helm_chart_resources/<namespace>/<name>')
@login_required
def get_helm_chart_resources(namespace, name):
    try:
        manifest_result = subprocess.run(
            ['/usr/local/bin/helm', 'get', 'manifest', name, '--namespace', namespace, '--kubeconfig', os.path.expanduser('~/.kube/config')],
            capture_output=True,
            text=True,
            check=True
        )
        manifest = manifest_result.stdout
        resources = []
        for doc in yaml.safe_load_all(manifest):
            if doc and 'kind' in doc and 'metadata' in doc and 'name' in doc['metadata']:
                resources.append({
                    'kind': doc['kind'],
                    'name': doc['metadata']['name']
                })
        return render_template('helm_chart_resources.html', chart_name=name, namespace=namespace, resources=resources)
    except Exception as e:
        return f"Error fetching resources for Helm chart {name} in namespace {namespace}: {e}"


@app.route('/compliance_reports')
@login_required
def compliance_reports():
    reports_dir = os.path.join(app.static_folder, 'goss_reports')
    default_report = 'aggregated_compliance_report.html'
    try:
        reports = sorted([f for f in os.listdir(reports_dir) if f.endswith('.html')])
        if default_report not in reports:
            default_report = None
            
        return render_template(
            'compliance_reports.html', 
            reports=reports, 
            default_report=default_report
        )
    except FileNotFoundError:
        flash('Compliance reports directory not found.', 'error')
        return render_template('compliance_reports.html', reports=[], default_report=None)

@app.route('/compliance_report/<report_name>')
@login_required
def view_compliance_report(report_name):
    reports_dir = os.path.expanduser('~/goss_reports')
    return send_from_directory(reports_dir, report_name)





@app.route('/run_upgrade_check', methods=['POST'])
@login_required
def run_upgrade_check():
    playbook_path = os.path.join(os.path.dirname(__file__), 'ansible_upgrade_check', 'check_upgrades.yml')
    inventory_path = os.path.join(os.path.dirname(__file__), 'inventory.ini')
    # Reports are now in /tmp
    reports_dir = os.path.join(os.path.dirname(__file__), 'ansible_upgrade_check', 'reports')
    
    try:
        # Clear old reports from /tmp
        for f in os.listdir(reports_dir):
            if f.endswith('_upgrade_check.txt'):
                os.remove(os.path.join(reports_dir, f))

        command = [
            os.path.expanduser('~/simple_kube_web_app/venv/bin/ansible-playbook'),
            '-i', inventory_path,
            '--user', SSH_USERNAME,
            '--private-key', SSH_KEY_PATH,
            '--limit', 'all:!nginx',
            '--extra-vars', 'ansible_python_interpreter=/usr/bin/python3',
            playbook_path
        ]
        subprocess.run(command, capture_output=True, text=True, check=True)
        flash('Successfully ran upgrade check.', 'success')

    except subprocess.CalledProcessError as e:
        error_details = f"Exit Code: {e.returncode}\nStdout:\n{e.stdout}\nStderr:\n{e.stderr}"
        flash(f"Error running Ansible playbook. Details:\n{error_details}", 'error')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'error')
        
    return redirect(url_for('upgrade_status'))

@app.route('/run_upgrade_check_all', methods=['POST'])
@login_required
def run_upgrade_check_all():
    task_id = str(uuid.uuid4())
    playbook_path = os.path.expanduser('~/ansible_upgrade_check/check_upgrades.yml')
    inventory_path = os.path.join(os.path.dirname(__file__), 'inventory.ini')
    
    # Exclude the nginx host from the upgrade check
    thread = threading.Thread(target=run_ansible_playbook_async, args=(task_id, 'upgrade_check', playbook_path, inventory_path, None, 'all:!nginx'))
    thread.start()
    return jsonify({'task_id': task_id, 'message': 'Upgrade check started for all hosts.'}), 202

@app.route('/run_unattended_upgrades/<hostname>', methods=['POST'])
@login_required
def run_unattended_upgrades(hostname):
    print(f"DEBUG: Attempting to run unattended upgrades for host: {hostname}")
    try:
        inventory_path = os.path.join(os.path.dirname(__file__), 'inventory.ini')
        is_local_connection = False
        ansible_host = None
        print(f"DEBUG: Opening inventory file: {inventory_path}")
        with open(inventory_path, 'r') as f:
            for line in f:
                if line.strip().startswith(hostname):
                    if 'ansible_connection=local' in line:
                        is_local_connection = True
                        print(f"DEBUG: Host {hostname} uses local connection.")
                        break
                    else:
                        import re
                        match = re.search(r'ansible_host=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', line)
                        if match:
                            ansible_host = match.group(1)
                            print(f"DEBUG: Found ansible_host: {ansible_host} for {hostname}")
                            break
            else:
                flash(f"Could not find host {hostname} in inventory.", 'error')
                print(f"ERROR: Could not find host {hostname} in inventory.")
                return redirect(url_for('upgrade_status'))

        command_to_run = 'sudo DEBIAN_FRONTEND=noninteractive unattended-upgrades'
        output = ""
        error_output = ""
        exit_status = 1 # Default to failure

        if is_local_connection:
            print(f"DEBUG: Executing local command for {hostname}: {command_to_run}")
            try:
                result = subprocess.run(command_to_run.split(), capture_output=True, text=True, check=False, timeout=60)
                output = result.stdout
                error_output = result.stderr
                exit_status = result.returncode
                print(f"DEBUG: Local command completed. Exit status: {exit_status}")
                print(f"DEBUG: STDOUT: {output}")
                print(f"DEBUG: STDERR: {error_output}")
            except subprocess.TimeoutExpired as e:
                flash(f"Local unattended upgrades on {hostname} timed out after 5 minutes. Output: {e.stdout}. Error: {e.stderr}", 'error')
                print(f"ERROR: Local command timed out: {e}")
                return render_template('unattended_upgrades_result.html', hostname=hostname, output=f"Timeout occurred. Output: {e.stdout}\nError: {e.stderr}")
            except Exception as e:
                flash(f"An unexpected error occurred during local command execution on {hostname}: {e}", 'error')
                print(f"ERROR: Unexpected error during local command execution on {hostname}: {e}")
                return redirect(url_for('upgrade_status'))
        else: # Remote connection via SSH
            if not ansible_host:
                flash(f"Could not extract ansible_host IP for {hostname} from inventory.", 'error')
                print(f"ERROR: Could not extract ansible_host IP for {hostname} from inventory.")
                return redirect(url_for('upgrade_status'))

            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                print(f"DEBUG: Attempting SSH connection to {ansible_host} as {SSH_USERNAME} with key {SSH_KEY_PATH}")
                ssh.connect(ansible_host, username=SSH_USERNAME, key_filename=SSH_KEY_PATH, timeout=10)
                print(f"DEBUG: SSH connection successful to {ansible_host}")
                print(f"DEBUG: Executing remote command: {command_to_run}")
                stdin, stdout, stderr = ssh.exec_command(command_to_run)
                
                output = stdout.read().decode('utf-8')
                error_output = stderr.read().decode('utf-8')
                
                exit_status = stdout.channel.recv_exit_status() # Wait for command to complete
                print(f"DEBUG: Remote command completed. Exit status: {exit_status}")
                print(f"DEBUG: STDOUT: {output}")
                print(f"DEBUG: STDERR: {error_output}")

            except paramiko.AuthenticationException:
                flash(f"Authentication failed for {hostname}. Check SSH key and username.", 'error')
                print(f"ERROR: Authentication failed for {hostname}.")
                return redirect(url_for('upgrade_status'))
            except paramiko.SSHException as e:
                flash(f"SSH connection error to {hostname}: {e}", 'error')
                print(f"ERROR: SSH connection error to {hostname}: {e}")
                return redirect(url_for('upgrade_status'))
            except Exception as e:
                flash(f"An unexpected error occurred during SSH command execution on {hostname}: {e}", 'error')
                print(f"ERROR: Unexpected error during SSH command execution on {hostname}: {e}")
                return redirect(url_for('upgrade_status'))
            finally:
                if ssh:
                    ssh.close()
                    print(f"DEBUG: SSH connection to {ansible_host} closed.")
        
        # After execution (either local or remote)
        if exit_status == 0:
            flash(f"Unattended upgrades on {hostname} completed successfully.", 'success')
        else:
            flash(f"Unattended upgrades on {hostname} failed with exit code {exit_status}. Error: {error_output}", 'error')
        
        return render_template('unattended_upgrades_result.html', hostname=hostname, output=output + "\n" + error_output)

    except FileNotFoundError:
        flash("Inventory file not found. Please ensure ~/kubecreate/inventory/local/hosts.ini exists.", 'error')
        print("ERROR: Inventory file not found: ~/kubecreate/inventory/local/hosts.ini")
        return redirect(url_for('upgrade_status'))
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'error')
        print(f"ERROR: An unexpected error occurred in run_unattended_upgrades: {e}")
        return redirect(url_for('upgrade_status'))

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
    ssh.connect(ansible_host, username=SSH_USERNAME, key_filename=SSH_KEY_PATH, timeout=10)
    return ssh, ansible_host

@app.route('/upgrade_status')
@login_required
def upgrade_status():
    inventory_path = os.path.join(os.path.dirname(__file__), 'inventory.ini')
    hosts = set() # Use a set to store unique hostnames
    try:
        with open(inventory_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('['):
                    # Extract hostname, which is the first word before any spaces or ansible_ variables
                    hostname = line.split(' ')[0]
                    hosts.add(hostname)
        hosts_list = sorted(list(hosts)) # Convert set to list and sort for consistent display
    except FileNotFoundError:
        flash("Inventory file not found. Please ensure inventory.ini exists in the application directory.", 'error')
        hosts_list = []
    except Exception as e:
        flash(f"Error reading inventory: {e}", 'error')
        hosts_list = []

    return render_template('upgrade_status.html', hosts_list=hosts_list)


@app.route('/get_all_updates')
@login_required
def get_all_updates():
    inventory_path = os.path.join(os.path.dirname(__file__), 'inventory.ini')
    hosts = set()
    try:
        with open(inventory_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('[') and 'nginx' not in line and 'endpoint' not in line:
                    hostname = line.split(' ')[0]
                    hosts.add(hostname)
    except FileNotFoundError:
        return jsonify({'error': 'Inventory file not found.'}), 500

    all_updates = {}
    for host in sorted(list(hosts)):
        try:
            ssh, ansible_host = get_ssh_connection(host)

            # Get all upgradable packages
            if ssh == 'local':
                command = 'apt list --upgradable'
                process = subprocess.run(command.split(), capture_output=True, text=True, check=False)
                upgradable_output = process.stdout + process.stderr
            else:
                stdin, stdout, stderr = ssh.exec_command('apt list --upgradable')
                upgradable_output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')

            # Get security updates
            if ssh == 'local':
                command = 'sudo unattended-upgrades --dry-run'
                process = subprocess.run(command.split(), capture_output=True, text=True, check=False)
                security_output = process.stdout + process.stderr
            else:
                stdin, stdout, stderr = ssh.exec_command('sudo unattended-upgrades --dry-run')
                security_output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                ssh.close()

            security_updates_list = []
            for line in security_output.splitlines():
                if "/usr/bin/dpkg" in line:
                    match = re.search(r'/var/cache/apt/archives/(.+?)_', line)
                    if match:
                        package_name = match.group(1)
                        if package_name not in security_updates_list:
                            security_updates_list.append(package_name)

            non_security_updates = []
            for line in upgradable_output.splitlines():
                if "/" in line and "[" in line and "]" in line:
                    try:
                        parts = line.split()
                        package_name_full = parts[0]
                        package_name = package_name_full.split('/')[0]
                        if package_name not in security_updates_list:
                            new_version = parts[1]
                            current_version_match = re.search(r'\[(.*)\]', line)
                            current_version = current_version_match.group(1) if current_version_match else "N/A"
                            non_security_updates.append({
                                'name': package_name,
                                'current_version': current_version,
                                'new_version': new_version
                            })
                    except IndexError:
                        print(f"WARNING: Could not parse line: {line}")
                        continue
            
            all_updates[host] = {
                'security_updates': security_updates_list,
                'other_updates': non_security_updates,
                'has_security_updates': len(security_updates_list) > 0
            }
        except Exception as e:
            all_updates[host] = {'error': str(e)}
            
    return jsonify(all_updates)

@app.route('/run_patch/<hostname>/<patch_type>', methods=['POST'])
@login_required
def run_patch(hostname, patch_type):
    task_id = str(uuid.uuid4())
    
    if patch_type == 'security':
        command_to_run = 'sudo unattended-upgrades --debug'
    elif patch_type == 'non-security':
        command_to_run = 'sudo apt-get update && sudo apt-get dist-upgrade -y'
    else:
        return jsonify({'message': 'Invalid patch type.'}), 400

    def run_patch_async(task_id, hostname, command_to_run, patch_type):
        running_tasks[task_id] = {'status': 'running', 'output': '', 'type': 'patch', 'hostname': hostname, 'patch_type': patch_type}
        try:
            ssh, ansible_host = get_ssh_connection(hostname)
            if ssh == 'local':
                process = subprocess.run(command_to_run, shell=True, capture_output=True, text=True, check=False)
                output = process.stdout + process.stderr
            else:
                stdin, stdout, stderr = ssh.exec_command(command_to_run)
                output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                ssh.close()
            
            # Save the output to a log file
            log_dir = os.path.join(os.path.dirname(__file__), 'patch_logs')
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            log_file = os.path.join(log_dir, f'{hostname}_{patch_type}_{timestamp}.log')
            with open(log_file, 'w') as f:
                f.write(output)

            running_tasks[task_id]['output'] = output
            running_tasks[task_id]['status'] = 'completed'
        except Exception as e:
            running_tasks[task_id]['status'] = 'error'
            running_tasks[task_id]['output'] = str(e)

    thread = threading.Thread(target=run_patch_async, args=(task_id, hostname, command_to_run, patch_type))
    thread.start()
    return jsonify({'task_id': task_id, 'message': f'Patching {patch_type} updates for {hostname} started.'}), 202

@app.route('/get_non_security_updates/<hostname>', methods=['POST'])
def get_non_security_updates(hostname):
    task_id = str(uuid.uuid4())
    running_tasks[task_id] = {'status': 'running', 'output': '', 'type': 'non_security_updates', 'hostname': hostname, 'packages': []}

    def run_non_security_updates_async(task_id, hostname):
        task = running_tasks[task_id]
        try:
            ssh, ansible_host = get_ssh_connection(hostname)

            # Get all upgradable packages
            if ssh == 'local':
                command = 'apt list --upgradable'
                process = subprocess.run(command.split(), capture_output=True, text=True, check=False)
                upgradable_output = process.stdout + process.stderr
            else:
                stdin, stdout, stderr = ssh.exec_command('apt list --upgradable')
                upgradable_output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')

            # Get security updates
            if ssh == 'local':
                command = 'sudo unattended-upgrades --dry-run'
                process = subprocess.run(command.split(), capture_output=True, text=True, check=False)
                security_output = process.stdout + process.stderr
            else:
                stdin, stdout, stderr = ssh.exec_command('sudo unattended-upgrades --dry-run')
                security_output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                ssh.close()

            security_updates_list = []
            for line in security_output.splitlines():
                if "Checking" in line or "Allowed origins" in line:
                    continue
                if re.match(r'^\s*$', line): # Skip empty lines
                    continue
                if "pkgs that will be upgraded:" in line.lower():
                    continue
                if "ubuntu" in line.lower() and "security" in line.lower():
                    security_updates_list.append(line.strip().split()[0])

            non_security_updates = []
            for line in upgradable_output.splitlines():
                if "/" in line and "[" in line and "]" in line:
                    try:
                        parts = line.split()
                        package_name_full = parts[0]
                        package_name = package_name_full.split('/')[0]
                        if package_name not in security_updates_list:
                            new_version = parts[1]
                            current_version_match = re.search(r'\[(.*)\]', line)
                            current_version = current_version_match.group(1) if current_version_match else "N/A"
                            non_security_updates.append({
                                'name': package_name,
                                'current_version': current_version,
                                'new_version': new_version
                            })
                    except IndexError:
                        print(f"WARNING: Could not parse line: {line}")
                        continue
            
            task['packages'] = non_security_updates
            task['status'] = 'completed'

        except Exception as e:
            task['status'] = 'error'
            task['output'] = f"An unexpected error occurred: {e}"
            print(f"ERROR: An unexpected error occurred in get_non_security_updates: {e}")

    thread = threading.Thread(target=run_non_security_updates_async, args=(task_id, hostname))
    thread.start()
    return jsonify({'task_id': task_id, 'message': f'Checking non-security updates for {hostname} started.'}), 202

@app.route('/non_security_updates_output/<task_id>')
def non_security_updates_output(task_id):
    task = running_tasks.get(task_id)
    if task and task.get('type') == 'non_security_updates':
        return render_template('non_security_updates_output.html', task=task)
    return "Task not found or output not available.", 404

@app.route('/download_report/<report_name>/<format>')
@login_required
def download_report(report_name, format):
    reports_dir = os.path.join(app.static_folder, 'goss_reports')
    report_path = os.path.join(reports_dir, report_name)

    if not os.path.exists(report_path):
        return "Report not found", 404

    if format == 'pdf':
        try:
            pdf = pdfkit.from_file(report_path, False)
            response = make_response(pdf)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename={report_name}.pdf'
            return response
        except Exception as e:
            return str(e), 500
    elif format == 'csv':
        try:
            with open(report_path, 'r') as f:
                soup = BeautifulSoup(f.read(), 'html.parser')
            
            output = StringIO()
            writer = csv.writer(output)
            
            for table in soup.find_all('table'):
                writer.writerow([]) # Add a blank row between tables
                headers = [header.text for header in table.find_all('th')]
                writer.writerow(headers)
                for row in table.find_all('tr'):
                    writer.writerow([data.text for data in row.find_all('td')])
            
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename={report_name}.csv'
            return response
        except Exception as e:
            return str(e), 500
    else:
        return "Invalid format", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
