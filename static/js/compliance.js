document.addEventListener('DOMContentLoaded', function() {
    const reportSelector = document.getElementById('reportSelector');
    const reportFrame = document.getElementById('report-frame');
    const runOscapScanButton = document.getElementById('runOscapScanButton');
    const playbookStatus = document.getElementById('playbookStatus');
    const playbookOutput = document.getElementById('playbookOutput');
    const oscapConfirmationModalElement = document.getElementById('oscapConfirmationModal');
    let oscapConfirmationModal;

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

    async function runPlaybook(url) {
        handlePlaybookStart();

        try {
            const response = await fetch(url, { method: 'POST' });
            const data = await response.json();

            if (response.status === 202) {
                updatePlaybookStatus(data.message + ' This may take a while...', 'info');
                if (playbookOutput) {
                    playbookOutput.style.display = 'block';
                }
                pollTaskStatus(data.task_id);
            } else {
                updatePlaybookStatus(`Error: ${data.message || 'Unknown error'}`, 'danger');
                setButtonState(runOscapScanButton, false);
            }
        } catch (error) {
            updatePlaybookStatus(`Network error: ${error.message}`, 'danger');
            setButtonState(runOscapScanButton, false);
        }
    }

    async function pollTaskStatus(taskId) {
        const interval = setInterval(async () => {
            try {
                const response = await fetch(`/get_task_status/${taskId}`);
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                const data = await response.json();

                if (data.status === 'running') {
                    updatePlaybookStatus('Playbook is running... (This may take a while)', 'info');
                    if (playbookOutput) playbookOutput.textContent = data.output;
                } else {
                    clearInterval(interval);
                    setButtonState(runOscapScanButton, false);
                    if (data.status === 'completed') {
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
                clearInterval(interval);
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
                    updatePlaybookStatus('OpenSCAP scan is already in progress...', 'info');
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
                reportFrame.src = this.value ? `/static/oscap_reports/${this.value}` : 'about:blank';
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

    if (runOscapScanButton) {
        runOscapScanButton.addEventListener('click', () => {
            if (oscapConfirmationModal) oscapConfirmationModal.show();
        });
    }

    const confirmRunOscapButton = document.getElementById('confirmRunOscapButton');
    if (confirmRunOscapButton) {
        confirmRunOscapButton.addEventListener('click', () => {
            if (oscapConfirmationModal) oscapConfirmationModal.hide();
            fetch('/run_oscap_scan', { method: 'POST' })
                .then(() => {
                    window.location.reload();
                });
        });
    }

    checkRunningTasks();
});
