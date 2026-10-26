const API_BASE = "http://127.0.0.1:5000";

async function loadThreats() {
    try {
        const response = await fetch(`${API_BASE}/api/threats`);
        if (!response.ok) throw new Error("Unable to load threats");
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "Threat loading failed");
        displayThreats(data.threats || []);
    } catch (error) {
        console.error("Threat Management Error:", error);
        document.getElementById("threatTable").innerHTML = `
            <tr><td colspan="6">Unable to connect to Flask backend. Make sure Flask is running on port 5000.</td></tr>
        `;
    }
}

async function analyzeThreat() {
    const input = document.getElementById("threatInput").value.trim();
    if (!input) {
        alert("Enter a URL, IP address, domain or hash.");
        return;
    }
    const button = document.querySelector(".input-row button");
    button.disabled = true;
    button.textContent = "Analyzing...";
    try {
        const response = await fetch(`${API_BASE}/api/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ indicator: input })
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.message || "Threat analysis failed");
        }
        displayResult(data.result);
        await loadThreats();
    } catch (error) {
        console.error("Analysis Error:", error);
        alert("Threat analysis failed: " + error.message);
    } finally {
        button.disabled = false;
        button.textContent = "Analyze Threat";
    }
}

function displayResult(result) {
    document.getElementById("resultCard").style.display = "block";
    document.getElementById("resultIndicator").textContent = result.indicator || "-";
    document.getElementById("resultType").textContent = result.threat_type || "-";
    document.getElementById("resultScore").textContent = `${result.risk_score ?? 0}/100`;
    document.getElementById("resultSeverity").textContent = result.severity || "-";
    document.getElementById("resultIOC").textContent = result.indicator_type || "-";
    document.getElementById("resultStatus").textContent = result.status || "-";
}

function displayThreats(threats) {
    const table = document.getElementById("threatTable");
    if (!threats.length) {
        table.innerHTML = `<tr><td colspan="6">No threats detected</td></tr>`;
        updateStatistics([]);
        return;
    }
    table.innerHTML = threats.map(threat => `
        <tr>
            <td>${escapeHTML(threat.indicator || "-")}</td>
            <td>${escapeHTML(threat.indicator_type || "-")}</td>
            <td>${escapeHTML(threat.threat_type || "-")}</td>
            <td>${threat.risk_score ?? 0}/100</td>
            <td>${escapeHTML(threat.severity || "-")}</td>
            <td>${escapeHTML(threat.status || "-")}</td>
        </tr>
    `).join("");
    updateStatistics(threats);
}

function updateStatistics(threats) {
    const critical = threats.filter(t => String(t.severity).toLowerCase() === "critical").length;
    const high = threats.filter(t => String(t.severity).toLowerCase() === "high").length;
    const medium = threats.filter(t => String(t.severity).toLowerCase() === "medium").length;
    const low = threats.filter(t => String(t.severity).toLowerCase() === "low").length;
    document.getElementById("totalThreats").textContent = threats.length;
    document.getElementById("criticalThreats").textContent = critical;
    document.getElementById("highThreats").textContent = high;
    document.getElementById("mediumThreats").textContent = medium;
    document.getElementById("lowThreats").textContent = low;
    const maximum = Math.max(critical, high, medium, low, 1);
    document.getElementById("criticalCount").textContent = critical;
    document.getElementById("highCount").textContent = high;
    document.getElementById("mediumCount").textContent = medium;
    document.getElementById("lowCount").textContent = low;
    document.getElementById("criticalBar").style.width = `${critical / maximum * 100}%`;
    document.getElementById("highBar").style.width = `${high / maximum * 100}%`;
    document.getElementById("mediumBar").style.width = `${medium / maximum * 100}%`;
    document.getElementById("lowBar").style.width = `${low / maximum * 100}%`;
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
    if (localStorage.getItem("fortnetLoggedIn") !== "true") {
        window.location.href = "login.html";
        return;
    }
    loadThreats();
});
