const REPORT_API =
    "http://127.0.0.1:5000";

document.addEventListener(
    "DOMContentLoaded",
    () => {
        if (localStorage.getItem("fortnetLoggedIn") !== "true") {
            window.location.href = "login.html";
            return;
        }
        loadReport();
    }
);

async function loadReport() {
    try {
        const response = await fetch(REPORT_API + "/api/dashboard");
        const data = await response.json();
        if (!data.success) return;

        const stats = data.statistics;
        document.getElementById("reportThreats").textContent = stats.active_threats;
        document.getElementById("reportIOCs").textContent = stats.iocs;
        const severity = stats.severity || {};
        const critical = severity.critical || 0;
        const high = severity.high || 0;
        const medium = severity.medium || 0;
        const low = severity.low || 0;
        document.getElementById("reportCritical").textContent = critical;
        document.getElementById("reportHigh").textContent = high;
        document.getElementById("reportCritical2").textContent = critical;
        document.getElementById("reportHigh2").textContent = high;
        document.getElementById("reportMedium").textContent = medium;
        document.getElementById("reportLow").textContent = low;
    } catch (error) {
        console.error("Report error:", error);
    }
}
