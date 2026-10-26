const OSINT_API = "http://127.0.0.1:5000";

document.addEventListener("DOMContentLoaded", () => {
    if (localStorage.getItem("fortnetLoggedIn") !== "true") {
        window.location.href = "login.html";
        return;
    }
    loadOSINTRecords();
    const collectBtn = document.getElementById("collectBtn");
    if (collectBtn) collectBtn.addEventListener("click", collectOSINT);
});

async function collectOSINT() {
    const collectBtn = document.getElementById("collectBtn");
    if (!collectBtn) return;
    collectBtn.disabled = true;
    collectBtn.textContent = "Collecting...";
    try {
        const response = await fetch(OSINT_API + "/api/osint/collect", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await response.json();
        if (!data.success) {
            alert(data.message || "OSINT collection failed.");
            return;
        }
        alert(data.message || "Intelligence collected successfully.");
        loadOSINTRecords();
    } catch (error) {
        console.error("OSINT collection error:", error);
        alert("Cannot connect to Fortnet backend. Make sure Flask is running.");
    } finally {
        collectBtn.disabled = false;
        collectBtn.textContent = "Collect Intelligence";
    }
}

async function loadOSINTRecords() {
    try {
        const response = await fetch(OSINT_API + "/api/osint/records");
        const data = await response.json();
        const container = document.getElementById("osintList");
        if (!container) return;
        if (!data.success || !Array.isArray(data.records) || !data.records.length) {
            container.innerHTML = `<p class="empty-message">Click "Collect Intelligence" to begin.</p>`;
            return;
        }
        container.innerHTML = data.records.map(record => `
            <div class="threat-item">
                <div><div class="threat-indicator">${escapeHTML(record.indicator || record.title || "-")}</div>
                    <div class="threat-meta">${escapeHTML(record.source || "OSINT Source")}</div></div>
                <div><div class="threat-meta">Type</div><div>${escapeHTML(record.indicator_type || "-")}</div></div>
                <div><div class="threat-meta">Threat</div><div>${escapeHTML(record.threat_type || "-")}</div></div>
                <div><div class="threat-meta">Severity</div><span class="severity ${getSeverityClass(record.severity)}">${escapeHTML(record.severity || "-")}</span></div>
            </div>
        `).join("");
    } catch (error) {
        console.error("OSINT load error:", error);
    }
}

function getSeverityClass(severity) {
    if (severity === "Critical") return "severity-critical";
    if (severity === "High") return "severity-high";
    if (severity === "Medium") return "severity-medium";
    return "severity-low";
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
