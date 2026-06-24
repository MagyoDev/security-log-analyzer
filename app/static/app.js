async function checkApiStatus() {
    const statusElement = document.getElementById("api-status");

    try {
        const response = await fetch("/api/health");
        await response.json();

        statusElement.textContent = "API Status: Online";
        statusElement.classList.remove("error");
        statusElement.classList.add("ok");
    } catch (error) {
        statusElement.textContent = "API Status: Offline";
        statusElement.classList.remove("ok");
        statusElement.classList.add("error");
    }
}

async function loadNetworkInterfaces() {
    const interfaceSelect = document.getElementById("network-interface");

    try {
        const response = await fetch("/api/interfaces");
        const data = await response.json();

        data.interfaces.forEach(function (iface) {
            const option = document.createElement("option");

            option.value = iface;
            option.textContent = iface;

            interfaceSelect.appendChild(option);
        });
    } catch (error) {
        console.error("Erro ao carregar interfaces:", error);
    }
}

async function fetchStatus() {
    const response = await fetch("/api/status");
    const data = await response.json();

    updateDashboard(data);
}


function updateDashboard(state) {
    const report = state.report;

    updateCards(state, report);
    updateCaptureControls(state);
    updateCaptureStatusPanel(state);

    renderTrafficDirection(report.direction_summary);
    renderProtocols(report.protocols);
    renderEndpoints(report.endpoints);
    renderFlows(report.flows);
    renderPorts(report.destination_ports);
    renderDnsQueries(report.dns_queries);
    renderTcpFlags(report.tcp_flags);
    renderPacketLengths(report.packet_lengths);
    renderFindings(report.findings);
}


function translateStatus(status) {
    const translations = {
        idle: "Aguardando",
        capturing: "Capturando",
        completed: "Finalizada",
        error: "Erro",
    };

    return translations[status] || "Desconhecido";
}


function updateCaptureControls(state) {
    const startButton = document.getElementById("start-capture-button");
    const stopButton = document.getElementById("stop-capture-button");
    const resetButton = document.getElementById("reset-button");
    const captureModeElement = document.getElementById("capture-mode");
    const packetCountElement = document.getElementById("packet-count");
    const networkInterfaceElement = document.getElementById("network-interface");
    const protocolFilterElement = document.getElementById("protocol-filter");
    const hostFilterElement = document.getElementById("host-filter");

    if (state.is_capturing) {
        startButton.disabled = true;
        stopButton.disabled = false;
        resetButton.disabled = true;
        captureModeElement.disabled = true;
        packetCountElement.disabled = true;
        networkInterfaceElement.disabled = true;
        protocolFilterElement.disabled = true;
        hostFilterElement.disabled = true;
    } else {
        startButton.disabled = false;
        stopButton.disabled = true;
        resetButton.disabled = false;
        captureModeElement.disabled = false;
        packetCountElement.disabled = false;
        networkInterfaceElement.disabled = false;
        protocolFilterElement.disabled = false;
        hostFilterElement.disabled = false;
    }
}

function updateCaptureStatusPanel(state) {
    const statusLabelElement = document.getElementById("capture-status-label");
    const activeInterfaceElement = document.getElementById("active-interface");
    const activeFilterElement = document.getElementById("active-filter");
    const startedAtElement = document.getElementById("started-at");
    const stoppedAtElement = document.getElementById("stopped-at");
    const errorMessageElement = document.getElementById("error-message");

    const translatedStatus = translateStatus(state.status);

    statusLabelElement.textContent = translatedStatus;
    statusLabelElement.className = `status-label ${state.status}`;

    activeInterfaceElement.textContent = state.iface || "Padrão";

    const filters = [];

    if (state.protocol_filter) {
        filters.push(`Protocolo: ${state.protocol_filter}`);
    }

    if (state.host_filter) {
        filters.push(`Host: ${state.host_filter}`);
    }

    if (filters.length === 0) {
        activeFilterElement.textContent = "Nenhum";
    } else {
        activeFilterElement.textContent = filters.join(" | ");
    }

    startedAtElement.textContent = state.started_at || "-";
    stoppedAtElement.textContent = state.stopped_at || "-";
    errorMessageElement.textContent = state.error_message || "-";
}

function updateCards(state, report) {
    const totalPacketsElement = document.getElementById("total-packets");
    const totalEndpointsElement = document.getElementById("total-endpoints");
    const totalFlowsElement = document.getElementById("total-flows");
    const riskLevelElement = document.getElementById("risk-level");
    const riskDescriptionElement = document.getElementById("risk-description");
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

    if (state.status === "capturing") {
        captureStatusTextElement.textContent = "Captura em andamento";
    } else if (state.status === "completed") {
        captureStatusTextElement.textContent = "Captura finalizada";
    } else if (state.status === "error") {
        captureStatusTextElement.textContent = "Erro na captura";
    } else {
        captureStatusTextElement.textContent = "Aguardando captura";
    }
}


function renderTrafficDirection(directionSummary) {
    const tableBody = document.getElementById("traffic-direction-table-body");

    tableBody.innerHTML = "";

    const rows = [
        ["IP local", directionSummary.local_ip || "N/A"],
        ["Entrada", directionSummary.inbound],
        ["Saída", directionSummary.outbound],
        ["Interno/Outro", directionSummary.internal_or_other],
    ];

    rows.forEach(function (row) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${row[0]}</td>
            <td>${row[1]}</td>
        `;

        tableBody.appendChild(tr);
    });
}


function renderProtocols(protocols) {
    const container = document.getElementById("protocols-list");

    container.innerHTML = "";

    if (!protocols || protocols.length === 0) {
        container.innerHTML = `<div class="placeholder">Aguardando dados...</div>`;
        return;
    }

    protocols.forEach(function (item) {
        const row = document.createElement("div");
        row.classList.add("protocol-row");

        row.innerHTML = `
            <div class="protocol-name">${item.protocol}</div>
            <div class="protocol-track">
                <div class="protocol-fill" style="width: ${item.percentage}%"></div>
            </div>
            <div class="protocol-percent">${item.percentage}%</div>
        `;

        container.appendChild(row);
    });
}


function renderEndpoints(endpoints) {
    const tableBody = document.getElementById("endpoints-table-body");

    tableBody.innerHTML = "";

    if (!endpoints || endpoints.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="5">Aguardando dados...</td>
            </tr>
        `;
        return;
    }

    endpoints.forEach(function (endpoint) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${endpoint.ip}</td>
            <td>${endpoint.hostname}</td>
            <td>${endpoint.sent}</td>
            <td>${endpoint.received}</td>
            <td>${endpoint.total}</td>
        `;

        tableBody.appendChild(tr);
    });
}


function renderFlows(flows) {
    const tableBody = document.getElementById("flows-table-body");

    tableBody.innerHTML = "";

    if (!flows || flows.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="3">Aguardando dados...</td>
            </tr>
        `;
        return;
    }

    flows.forEach(function (flow) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${flow.endpoint_a}</td>
            <td>${flow.endpoint_b}</td>
            <td>${flow.packets}</td>
        `;

        tableBody.appendChild(tr);
    });
}


function renderPorts(ports) {
    const tableBody = document.getElementById("ports-table-body");

    tableBody.innerHTML = "";

    if (!ports || ports.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="4">Aguardando dados...</td>
            </tr>
        `;
        return;
    }

    ports.forEach(function (port) {
        const tr = document.createElement("tr");
        const protocolClass = String(port.protocol).toLowerCase();

        tr.innerHTML = `
            <td>${port.port}</td>
            <td><span class="badge ${protocolClass}">${port.protocol}</span></td>
            <td>${port.service}</td>
            <td>${port.packets}</td>
        `;

        tableBody.appendChild(tr);
    });
}


function renderDnsQueries(dnsQueries) {
    const tableBody = document.getElementById("dns-table-body");

    tableBody.innerHTML = "";

    const entries = Object.entries(dnsQueries || {});

    if (entries.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="2">Nenhuma consulta DNS capturada.</td>
            </tr>
        `;
        return;
    }

    entries.forEach(function ([domain, count]) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${domain}</td>
            <td>${count}</td>
        `;

        tableBody.appendChild(tr);
    });
}


function renderTcpFlags(tcpFlags) {
    const tableBody = document.getElementById("tcp-flags-table-body");

    tableBody.innerHTML = "";

    const entries = Object.entries(tcpFlags || {});

    if (entries.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="2">Nenhuma flag TCP capturada.</td>
            </tr>
        `;
        return;
    }

    entries.forEach(function ([flag, count]) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${flag}</td>
            <td>${count}</td>
        `;

        tableBody.appendChild(tr);
    });
}


function renderPacketLengths(packetLengths) {
    const tableBody = document.getElementById("packet-lengths-table-body");

    tableBody.innerHTML = "";

    const rows = [
        ["Menor pacote", `${packetLengths.min} bytes`],
        ["Maior pacote", `${packetLengths.max} bytes`],
        ["Média", `${packetLengths.average} bytes`],
    ];

    rows.forEach(function (row) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${row[0]}</td>
            <td>${row[1]}</td>
        `;

        tableBody.appendChild(tr);
    });

    const buckets = Object.entries(packetLengths.buckets || {});

    buckets.forEach(function ([range, count]) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${range}</td>
            <td>${count}</td>
        `;

        tableBody.appendChild(tr);
    });
}


function renderFindings(findings) {
    const container = document.getElementById("findings-list");

    container.innerHTML = "";

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="alert success">
                Nenhum alerta detectado.
            </div>
        `;
        return;
    }

    findings.forEach(function (finding) {
        const div = document.createElement("div");

        if (finding === "Nenhum alerta detectado.") {
            div.classList.add("alert", "success");
        } else {
            div.classList.add("alert", "warning");
        }

        div.textContent = finding;

        container.appendChild(div);
    });
}

async function startCapture() {
    const modeElement = document.getElementById("capture-mode");
    const packetCountElement = document.getElementById("packet-count");
    const networkInterfaceElement = document.getElementById("network-interface");
    const protocolFilterElement = document.getElementById("protocol-filter");
    const hostFilterElement = document.getElementById("host-filter");

    const mode = modeElement.value;
    const packetLimit = Number(packetCountElement.value);
    const iface = networkInterfaceElement.value || null;
    const protocolFilter = protocolFilterElement.value || null;
    const hostFilter = hostFilterElement.value.trim() || null;

    if (mode === "fixed" && (!packetLimit || packetLimit < 1)) {
        alert("Informe uma quantidade válida de pacotes.");
        return;
    }

    const response = await fetch("/api/start", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            mode: mode,
            packet_limit: packetLimit,
            iface: iface,
            protocol_filter: protocolFilter,
            host_filter: hostFilter
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


async function resetDashboard() {
    const response = await fetch("/api/reset", {
        method: "POST"
    });

    const data = await response.json();
    updateDashboard(data.state);
}


function exportReport(format) {
    const exportUrl = `/api/export/${format}`;
    window.location.href = exportUrl;
}


function setupEventListeners() {
    const startButton = document.getElementById("start-capture-button");
    const stopButton = document.getElementById("stop-capture-button");
    const resetButton = document.getElementById("reset-button");
    const exportButtons = document.querySelectorAll(".export-button");

    startButton.addEventListener("click", function () {
        startCapture();
    });

    stopButton.addEventListener("click", function () {
        stopCapture();
    });

    resetButton.addEventListener("click", function () {
        resetDashboard();
    });

    exportButtons.forEach(function (button) {
        button.addEventListener("click", function () {
            const format = button.dataset.format;
            exportReport(format);
        });
    });
}


checkApiStatus();
loadNetworkInterfaces();
fetchStatus();
setupEventListeners();

setInterval(fetchStatus, 2000);