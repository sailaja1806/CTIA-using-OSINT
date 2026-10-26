const DASHBOARD_API_URL = "http://127.0.0.1:5000";
const WATCHLIST_KEY = "fortnetWatchlist";

document.addEventListener("DOMContentLoaded", () => {
    checkLogin();
    loadDashboardUser();
    loadDashboardStatistics();
    loadRecentThreats();
    initWatchlist();
    initIncidentPulse();
    initThreatSourceTracker();
    startLiveClock();
});

function checkLogin() {
    if (localStorage.getItem("fortnetLoggedIn") !== "true") {
        window.location.href = "login.html";
    }
}

function loadDashboardUser() {
    const userData = localStorage.getItem("fortnetCurrentUser");
    if (!userData) return;
    try {
        const user = JSON.parse(userData);
        const userName = document.getElementById("userName");
        if (userName) userName.textContent = user.name;
    } catch (error) {
        console.error(error);
    }
}

async function loadDashboardStatistics() {
    try {
        const response = await fetch(DASHBOARD_API_URL + "/api/dashboard");
        const data = await response.json();
        if (!data.success) return;

        const statistics = data.statistics || {};
        setText("activeThreats", statistics.active_threats || 0);
        setText("alerts", statistics.alerts || 0);
        setText("iocs", statistics.iocs || 0);
        setText("users", statistics.users || 0);

        const severity = statistics.severity || {};
        const low = severity.low || 0;
        const medium = severity.medium || 0;
        const high = severity.high || 0;
        const critical = severity.critical || 0;
        setText("lowCount", low);
        setText("mediumCount", medium);
        setText("highCount", high);
        setText("criticalCount", critical);

        const maximum = Math.max(low, medium, high, critical, 1);
        setBarWidth("lowBar", low, maximum);
        setBarWidth("mediumBar", medium, maximum);
        setBarWidth("highBar", high, maximum);
        setBarWidth("criticalBar", critical, maximum);
    } catch (error) {
        console.error("Dashboard error:", error);
    }
}

async function loadRecentThreats() {
    try {
        const response = await fetch(DASHBOARD_API_URL + "/api/threats");
        const data = await response.json();
        const tbody = document.getElementById("recentThreats");
        if (!tbody) return;

        if (!data.success || !Array.isArray(data.threats) || !data.threats.length) {
            tbody.innerHTML = `<tr><td colspan="6">No threats detected yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.threats.slice(0, 5).map(threat => `
            <tr>
                <td>${escapeHTML(threat.indicator || "-")}</td>
                <td>${escapeHTML(threat.indicator_type || "-")}</td>
                <td>${escapeHTML(threat.threat_type || "-")}</td>
                <td>${escapeHTML(threat.risk_score ?? 0)}</td>
                <td><span class="severity ${getSeverityClass(threat.severity)}">${escapeHTML(threat.severity || "-")}</span></td>
                <td>${escapeHTML(threat.status || "-")}</td>
            </tr>
        `).join("");
    } catch (error) {
        console.error("Recent threats error:", error);
    }
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

function setBarWidth(id, value, maximum) {
    const bar = document.getElementById(id);
    if (bar) bar.style.width = Math.max(0, (value / maximum) * 100) + "%";
}

function getSeverityClass(severity) {
    if (severity === "Critical") return "severity-critical";
    if (severity === "High") return "severity-high";
    if (severity === "Medium") return "severity-medium";
    return "severity-low";
}

function startLiveClock() {
    const clock = document.getElementById("liveClock");
    if (!clock) return;
    const updateClock = () => {
        clock.textContent = new Date().toLocaleString([], {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        });
    };
    updateClock();
    setInterval(updateClock, 30000);
}

function initIncidentPulse() {
    const escalated = document.getElementById("pulseEscalated");
    const resolved = document.getElementById("pulseResolved");
    const sla = document.getElementById("pulseSla");
    const liveEscalated = 2 + Math.floor(Math.random() * 4);
    const liveResolved = 5 + Math.floor(Math.random() * 6);
    const liveSla = 90 + Math.floor(Math.random() * 9);
    if (escalated) escalated.textContent = String(liveEscalated);
    if (resolved) resolved.textContent = String(liveResolved);
    if (sla) sla.textContent = `${liveSla}%`;

    setInterval(() => {
        const nextEscalated = 1 + Math.floor(Math.random() * 6);
        const nextResolved = 3 + Math.floor(Math.random() * 8);
        const nextSla = 88 + Math.floor(Math.random() * 10);
        if (escalated) escalated.textContent = String(nextEscalated);
        if (resolved) resolved.textContent = String(nextResolved);
        if (sla) sla.textContent = `${nextSla}%`;
    }, 18000);
}

function initThreatSourceTracker() {
    const sourceData = [
        { name: "USA", score: 86, status: "Monitor" },
        { name: "Germany", score: 74, status: "Review" },
        { name: "India", score: 81, status: "Escalate" },
        { name: "Brazil", score: 69, status: "Monitor" },
        { name: "Singapore", score: 91, status: "Critical" }
    ];
    const list = document.getElementById("threatSourceList");
    const critical = document.getElementById("sourceCritical");
    const monitored = document.getElementById("sourceMonitored");
    const render = () => {
        if (!list) return;
        list.innerHTML = sourceData.map(item => `
            <div class="geo-card">
                <div class="geo-header"><span class="geo-dot"></span><strong>${escapeHTML(item.name)}</strong></div>
                <div class="geo-score">${item.score}</div>
                <span class="source-pill ${item.status.toLowerCase()}">${escapeHTML(item.status)}</span>
            </div>
        `).join("");
        if (critical) critical.textContent = sourceData.filter(item => item.status === "Critical").length;
        if (monitored) monitored.textContent = sourceData.filter(item => item.status === "Monitor").length;
    };
    render();
    setInterval(() => {
        sourceData.forEach(item => {
            item.score = Math.max(50, Math.min(99, item.score + (Math.random() > 0.5 ? 3 : -3)));
            const statuses = ["Monitor", "Review", "Escalate", "Critical"];
            item.status = statuses[Math.floor(Math.random() * statuses.length)];
        });
        render();
    }, 15000);
}

function initWatchlist() {
    const form = document.getElementById("watchlistForm");
    const list = document.getElementById("watchlistList");
    const clearButton = document.getElementById("clearWatchlist");
    if (!form || !list) return;
    renderWatchlist();
    form.addEventListener("submit", function(event) {
        event.preventDefault();
        const name = document.getElementById("watchlistName").value.trim();
        const severity = document.getElementById("watchlistSeverity").value;
        const status = document.getElementById("watchlistStatus").value;
        const notes = document.getElementById("watchlistNotes").value.trim();
        if (!name) return;
        const items = getWatchlist();
        items.unshift({ name, severity, status, notes, createdAt: new Date().toISOString() });
        localStorage.setItem(WATCHLIST_KEY, JSON.stringify(items));
        form.reset();
        renderWatchlist();
    });
    if (clearButton) {
        clearButton.addEventListener("click", function() {
            localStorage.removeItem(WATCHLIST_KEY);
            renderWatchlist();
        });
    }
}

function getWatchlist() {
    try {
        const raw = localStorage.getItem(WATCHLIST_KEY);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        console.error("Watchlist parse error:", error);
        return [];
    }
}

function renderWatchlist() {
    const list = document.getElementById("watchlistList");
    if (!list) return;
    const items = getWatchlist();
    setText("watchlistCount", items.length);
    setText("watchlistCritical", items.filter(item => item.severity === "Critical").length);
    setText("watchlistMonitoring", items.filter(item => item.status === "Monitoring").length);
    if (!items.length) {
        list.innerHTML = `<div class="empty-message">No assets are currently in the watchlist.</div>`;
        return;
    }
    list.innerHTML = items.map(item => `
        <div class="watch-item" data-level="${escapeHTML(item.severity)}">
            <div><div class="watch-item-name">${escapeHTML(item.name)}</div>
                <div class="watch-item-meta">${escapeHTML(item.notes || "No notes provided")}</div></div>
            <div class="watch-item-badges">
                <span class="severity ${getSeverityClass(item.severity)}">${escapeHTML(item.severity)}</span>
                <span class="watch-status">${escapeHTML(item.status)}</span>
            </div>
        </div>
    `).join("");
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
