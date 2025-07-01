# Nimbix Kube GUI

This is a simple Flask-based web application that provides a graphical user interface to view and manage various Kubernetes resources in your cluster.

## How it Works

The application is a single-page Flask application that uses the official Python Kubernetes client library to interact with your Kubernetes cluster. It reads your kubeconfig file (by default from `~/.kube/config`) to authenticate with the cluster. For node-specific operations like rebooting or checking for required updates, the application uses the Paramiko library to SSH into the nodes.

The application also integrates with Ansible to perform more complex tasks:

*   **GOSS Compliance:** Runs an Ansible playbook to execute GOSS tests on your nodes and generate compliance reports.
*   **Upgrade Checks:** Uses an Ansible playbook to check for available package upgrades on your nodes.

All long-running tasks, like running Ansible playbooks, are executed asynchronously in the background using Python's `threading` module to avoid blocking the web interface. The status of these tasks can be monitored through the web UI.

## Features

*   **Login/Logout system with username "admin" and a blank password.**
*   View Pods and their logs
*   **Delete Pods**
*   View Deployments
*   **Rollout Restart and Delete Deployments**
*   View Services
*   View Nodes
*   **Node Management: Cordon, Uncordon, Reboot, Check Reboot Status, Get Last Reboot Time**
*   View Persistent Volume Claims (PVCs)
*   View ConfigMaps
*   View StatefulSets
*   **Rollout Restart and Delete StatefulSets**
*   View DaemonSets
*   **Rollout Restart and Delete DaemonSets**
*   View Jobs
*   View Secrets
*   View Events
*   **View and Delete Helm Charts**
*   "Describe" action for all resources to view their full YAML definition.
*   Professional look using Bootstrap.
*   **Search functionality on all resource pages to filter by name (and message for events).**
*   **Upgrade Status page to view pending security and non-security updates for each host.**
*   **Compliance Reports page to view GOSS compliance reports, with the ability to download reports in PDF and CSV format.**

## Configuration Variables

The application now uses environment variables for sensitive paths and credentials, enhancing security and flexibility. You can configure the following:

*   `KUBECONFIG_PATH`: Path to your Kubernetes configuration file (default: `~/.kube/config`)
*   `SSH_KEY_PATH`: Path to the SSH private key used for node operations (default: `~/.ssh/id_rsa`)
*   `SSH_USERNAME`: Username for SSH connections to nodes (default: `keith`)

These variables can be set in your environment before running the application, for example:

```bash
export KUBECONFIG_PATH=/path/to/your/kube/config
export SSH_KEY_PATH=/path/to/your/ssh/key
export SSH_USERNAME=your_ssh_username
```

## Setup and Running

Follow these steps to set up and run the application:

1.  **Navigate to the application directory:**

    ```bash
    cd simple_kube_web_app
    ```

2.  **Create a Python virtual environment:**

    ```bash
    python3 -m venv venv
    ```

3.  **Activate the virtual environment:**

    ```bash
    source venv/bin/activate
    ```

4.  **Install the required Python packages:**

    ```bash
    pip install -r requirements.txt
    ```

5.  **Ensure your Kubernetes configuration is accessible:**
    The application uses your `~/.kube/config` file to connect to your Kubernetes cluster. Make sure this file exists and is correctly configured.

6.  **Run the Flask application:**

    ```bash
    python3 app.py
    ```

    The application will run on `http://0.0.0.0:5001`, meaning it will be accessible from any IP address on your network at port `5001`.

7.  **Access the application:**

    Open your web browser and go to `http://<your-machine-ip>:5001` (e.g., `http://192.168.122.190:5001`).

## Stopping the Application

To stop the application, you can usually press `Ctrl+C` in the terminal where it's running. If you ran it in the background, you'll need to find its process ID and kill it:

1.  **Find the process ID:**

    ```bash
    pgrep -f simple_kube_web_app/app.py
    ```

2.  **Kill the process (replace `<PID>` with the actual process ID):**

    ```bash
    kill <PID>
    ```
