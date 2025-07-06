document.addEventListener('DOMContentLoaded', function() {
    const reportSelector = document.getElementById('reportSelector');
    const reportFrame = document.getElementById('report-frame');
    const runOscapScanButton = document.getElementById('runOscapScanButton');
    const playbookStatus = document.getElementById('playbookStatus');
    const playbookOutput = document.getElementById('playbookOutput');
    const oscapConfirmationModalElement = document.getElementById('oscapConfirmationModal');
    let oscapConfirmationModal;
    let pollInterval = null; // Variable to hold the polling interval

    if (oscapConfirmationModalElement) {
        oscapConfirmationModal = new bootstrap.Modal(oscapConfirmationModalElement);
    }

    function setButtonState(button, isRunning) {
        if (button) {
            button.disabled = isRunning;
        }
    }

    function updatePlaybookStatus(message, type) {
        if (playbookStatus) {
            playbookStatus.className = `mt-3 alert alert-${type}`;
            playbookStatus.textContent = message;
            playbookStatus.classList.remove('d-none');
        }
    }

    function handlePlaybookStart() {
        setButtonState(runOscapScanButton, true);
        updatePlaybookStatus('Starting playbook...', 'info');
        if (playbookOutput) {
            playbookOutput.style.display = 'none';
            playbookOutput.textContent = '';
        }
    }

    async function pollTaskStatus(taskId) {
        if (pollInterval) {
            clearInterval(pollInterval); // Clear any existing interval
        }

        pollInterval = setInterval(async () => {
            try {
                const response = await fetch(`/get_task_status/${taskId}`);
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                const data = await response.json();

                if (data.status === 'running') {
                    let message = 'Playbook is running';
                    if (data.hosts && data.hosts.length > 0) {
                        message += ` on hosts: ${data.hosts.join(', ')}`;
                    }
                    message += ' (This may take a while)';
                    updatePlaybookStatus(message, 'info');
                    if (playbookOutput) playbookOutput.textContent = data.output;
                } else {
                    clearInterval(pollInterval);
                    pollInterval = null;
                    setButtonState(runOscapScanButton, false);
                    if (data.status === 'completed' || data.status === 'completed_and_reloaded') {
                        updatePlaybookStatus('Playbook completed successfully! Page will reload.', 'success');
                        setTimeout(() => window.location.reload(), 2000);
                    } else if (data.status === 'failed' || data.status === 'error') {
                        updatePlaybookStatus(`Playbook ${data.status}! Check output for details.`, 'danger');
                        if (playbookOutput) {
                            playbookOutput.textContent = data.output;
                            playbookOutput.style.display = 'block';
                        }
                    } else {
                        updatePlaybookStatus('Task not found.', 'danger');
                    }
                }
                if (playbookOutput && playbookOutput.style.display === 'block') {
                    playbookOutput.scrollTop = playbookOutput.scrollHeight;
                }
            } catch (error) {
                clearInterval(pollInterval);
                pollInterval = null;
                updatePlaybookStatus(`Error polling status: ${error.message}`, 'danger');
                setButtonState(runOscapScanButton, false);
            }
        }, 5000);
    }

    async function checkRunningTasks() {
        try {
            const response = await fetch('/get_all_task_statuses');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const tasks = await response.json();
            for (const taskId in tasks) {
                if (tasks[taskId].type === 'oscap' && tasks[taskId].status === 'running') {
                    setButtonState(runOscapScanButton, true);
                    const hosts = tasks[taskId].hosts ? `: ${tasks[taskId].hosts.join(', ')}` : '';
                    updatePlaybookStatus(`OpenSCAP scan is already in progress on hosts${hosts}...`, 'info');
                    if (playbookOutput) playbookOutput.style.display = 'block';
                    pollTaskStatus(taskId);
                    break;
                }
            }
        } catch (error) {
            console.error('Error checking running tasks:', error);
            updatePlaybookStatus('Could not check for running tasks. Please refresh the page.', 'warning');
        }
    }

    // Event Listeners
    if (reportSelector) {
        reportSelector.addEventListener('change', function() {
            if (reportFrame) {
                reportFrame.src = this.value ? `/view_oscap_report/${this.value}` : 'about:blank';
            }
        });
    }

    const downloadPdf = document.getElementById('downloadPdf');
    if (downloadPdf) {
        downloadPdf.addEventListener('click', function(e) {
            e.preventDefault();
            if (reportSelector && reportSelector.value) {
                window.location.href = `/download_report/${reportSelector.value}/pdf`;
            }
        });
    }

    const cancelButtons = document.querySelectorAll('.cancel-scan');
    if (cancelButtons) {
        cancelButtons.forEach(button => {
            button.addEventListener('click', () => {
                if (oscapConfirmationModal) {
                    oscapConfirmationModal.hide();
                }
            });
        });
    }

    if (runOscapScanButton) {
        runOscapScanButton.addEventListener('click', () => {
            if (oscapConfirmationModal) oscapConfirmationModal.show();
        });
    }

    const confirmRunOscapButton = document.getElementById('confirmRunOscapButton');
    if (confirmRunOscapButton) {
        confirmRunOscapButton.addEventListener('click', () => {
            if (oscapConfirmationModal) oscapConfirmationModal.hide();
            const hostSelector = document.getElementById('hostSelector');
            const selectedHosts = [...hostSelector.options].filter(option => option.selected).map(option => option.value);

            if (selectedHosts.length === 0) {
                alert('Please select at least one host to scan.');
                return;
            }

            const formData = new FormData();
            selectedHosts.forEach(host => {
                formData.append('selected_hosts', host);
            });

            if (pollInterval) {
                clearInterval(pollInterval);
                pollInterval = null;
            }

            fetch('/run_oscap_scan', {
                method: 'POST',
                body: formData,
                redirect: 'follow'
            })
            .then(response => {
                if (response.redirected) {
                    window.location.reload();
                } else if (response.ok || response.status === 409) {
                    return response.json().then(data => {
                        if (data.task_id) {
                            handlePlaybookStart();
                            updatePlaybookStatus(data.message, 'info');
                            if (playbookOutput) {
                                playbookOutput.style.display = 'block';
                            }
                            pollTaskStatus(data.task_id);
                        } else if (data.message) {
                            updatePlaybookStatus(data.message, 'warning');
                            setButtonState(runOscapScanButton, false);
                        }
                    });
                } else {
                    throw new Error('An unexpected server error occurred.');
                }
            })
            .catch(error => {
                updatePlaybookStatus(error.message, 'danger');
                setButtonState(runOscapScanButton, false);
            });
        });
    }

    checkRunningTasks();
});