const ANALYSIS_API =
    "http://127.0.0.1:5000";

document.addEventListener(
    "DOMContentLoaded",
    () => {
        if (localStorage.getItem("fortnetLoggedIn") !== "true") {
            window.location.href = "login.html";
            return;
        }
        const form = document.getElementById("analysisForm");
        if (form) form.addEventListener("submit", analyzeIndicator);
    }
);

async function analyzeIndicator(event) {
    event.preventDefault();
    const indicator = document.getElementById("analysisIndicator").value.trim();
    const button = document.getElementById("analyzeBtn");
    if (!indicator) {
        alert("Please enter an indicator.");
        return;
    }
    button.disabled = true;
    button.textContent = "Analyzing...";
    try {
        const response = await fetch(ANALYSIS_API + "/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ indicator })
        });
        const data = await response.json();
        if (!data.success) {
            alert(data.message || "Analysis failed.");
            return;
        }
        displayAnalysisResult(data.result);
    } catch (error) {
        console.error("Analysis error:", error);
        alert("Cannot connect to Fortnet backend. Make sure Flask is running.");
    } finally {
        button.disabled = false;
        button.textContent = "Analyze Threat";
    }
}

function displayAnalysisResult(result) {
    document.getElementById("resultPanel").style.display = "block";
    document.getElementById("resultIndicatorType").textContent = result.indicator_type;
    document.getElementById("resultStatus").textContent = result.status;
    document.getElementById("resultThreatType").textContent = result.threat_type;
    document.getElementById("resultSeverity").textContent = result.severity;
    document.getElementById("resultRiskScore").textContent = result.risk_score;
    document.getElementById("maliciousCount").textContent = result.detections.malicious;
    document.getElementById("suspiciousCount").textContent = result.detections.suspicious;
    document.getElementById("harmlessCount").textContent = result.detections.harmless;
    document.getElementById("undetectedCount").textContent = result.detections.undetected;
    const severityElement = document.getElementById("resultSeverity");
    severityElement.className = "severity " + getSeverityClass(result.severity);
    if (result.alert_created) {
        alert("High-risk threat detected. An alert has been automatically created.");
    }
}

function getSeverityClass(severity) {
    if (severity === "Critical") return "severity-critical";
    if (severity === "High") return "severity-high";
    if (severity === "Medium") return "severity-medium";
    return "severity-low";
}
