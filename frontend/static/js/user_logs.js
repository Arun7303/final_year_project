function fetchLogs() {
    fetch(`/user_details/{{ user_id }}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById("logs").textContent = data.logs || "No logs available.";
            document.getElementById("network_traffic").textContent = data.network_traffic || "No network data available.";
        })
        .catch(error => console.error("Error fetching logs:", error));
}

fetchLogs();
setInterval(fetchLogs, 10000); // Refresh every 10 seconds
