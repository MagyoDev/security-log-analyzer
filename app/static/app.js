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

    if (state.is_capturing) {
        captureStatusTextElement.textContent = "Captura em andamento";
    } else {
        captureStatusTextElement.textContent = "Aguardando captura";
    }
}


async function startCapture() {
    const response = await fetch("/api/start", {
        method: "POST"
    });

    const data = await response.json();

    updateDashboard(data.state);
}


function setupEventListeners() {
    const startButton = document.getElementById("start-capture-button");

    startButton.addEventListener("click", function () {
        startCapture();
    });
}


checkApiStatus();
fetchStatus();
setupEventListeners();