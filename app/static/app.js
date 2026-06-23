async function checkApiStatus() {
    const statusElement = document.getElementById("api-status");

    try {
        const response = await fetch("/api/health");
        const data = await response.json();

        statusElement.textContent = `API Status: Online`;
        statusElement.classList.remove("error");
        statusElement.classList.add("ok");
    } catch (error) {
        statusElement.textContent = "API Status: Offline";
        statusElement.classList.remove("ok");
        statusElement.classList.add("error");
    }
}


async function fetchStatus() {
    const response = await fetch("/api/status");
    const data = await response.json();

    updateDashboard(data);
}


function updateDashboard(state) {
    const report = state.report;

    const totalPacketsElement = document.getElementById("total-packets");
    const totalEndpointsElement = document.getElementById("total-endpoints");
    const totalFlowsElement = document.getElementById("total-flows");
    const riskLevelElement = document.getElementById("risk-level");
    const captureStatusTextElement = document.getElementById("capture-status-text");

    totalPacketsElement.textContent = report.total_packets;
    totalEndpointsElement.textContent = report.endpoints.length;
    totalFlowsElement.textContent = report.flows.length;
    riskLevelElement.textContent = report.risk_level;

    if (report.findings.length > 0) {
        riskDescriptionElement.textContent = report.findings[0];
    } else {
        riskDescriptionElement.textContent = "Nenhum alerta crítico";
    }

    if (state.is_capturing) {
        captureStatusTextElement.textContent = "Captura em andamento";
    } else if (state.stopped_at) {
        captureStatusTextElement.textContent = "Captura finalizada";
    } else {
        captureStatusTextElement.textContent = "Aguardando captura";
    }
}


async function startCapture() {
    const modeElement = document.getElementById("capture-mode");
    const packetCountElement = document.getElementById("packet-count");

    const mode = modeElement.value;
    const packetLimit = Number(packetCountElement.value);

    const response = await fetch("/api/start", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            mode: mode,
            packet_limit: packetLimit
        })
    });

    const data = await response.json();
    updateDashboard(data.state);
}


async function stopCapture() {
    const response = await fetch("/api/stop", {
        method: "POST"
    });

    const data = await response.json();
    updateDashboard(data.state);
}


function setupEventListeners() {
    const startButton = document.getElementById("start-capture-button");
    const stopButton = document.getElementById("stop-capture-button");

    startButton.addEventListener("click", function () {
        startCapture();
    });

    stopButton.addEventListener("click", function () {
        stopCapture();
    });
}


checkApiStatus();
fetchStatus();
setupEventListeners();

setInterval(fetchStatus, 2000);