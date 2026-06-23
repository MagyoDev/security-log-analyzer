async function checkApiStatus() {
    const statusElement = document.getElementById("api-status");

    try{
        const response = await fetch("/api/healt");
        const data = await response.json();

        statusElement.textContent = `${data.status.toUpperCase()} — ${data.app}`;
        statusElement.classList.add("ok");
    } catch (error) {
        statusElement.textContent = "API Status: Offline";
        statusElement.classList.add("error");
    }
}

checkApiStatus();