const ALERT_API =
    "http://127.0.0.1:5000";


document.addEventListener(
    "DOMContentLoaded",
    () => {

        if (
            localStorage.getItem(
                "fortnetLoggedIn"
            ) !== "true"
        ) {

            window.location.href =
                "login.html";

            return;

        }

        loadAlerts();

        document
            .getElementById(
                "refreshAlerts"
            )
            ?.addEventListener(
                "click",
                loadAlerts
            );

    }
);


async function loadAlerts() {

    try {

        const response =
            await fetch(
                ALERT_API +
                "/api/alerts"
            );

        const data =
            await response.json();


        if (!data.success) {
            return;
        }

        renderAlerts(
            data.alerts
        );


    } catch (error) {

        console.error(error);

    }

}


function renderAlerts(alerts) {

    const list =
        document.getElementById(
            "alertList"
        );


    document.getElementById(
        "totalAlerts"
    ).textContent =
        alerts.length;


    const critical =
        alerts.filter(
            alert =>
                alert.severity ===
                "Critical"
        ).length;


    const open =
        alerts.filter(
            alert =>
                alert.status !==
                "Resolved"
        ).length;


    document.getElementById(
        "criticalAlerts"
    ).textContent =
        critical;


    document.getElementById(
        "openAlerts"
    ).textContent =
        open;


    if (alerts.length === 0) {

        list.innerHTML = `
            <p class="empty-message">
                No security alerts.
            </p>
        `;

        return;

    }


    list.innerHTML = "";


    alerts.forEach(alert => {

        const item =
            document.createElement(
                "div"
            );

        item.className =
            "alert-item";


        item.innerHTML = `

            <div>

                <span class="
                    severity
                    ${getSeverityClass(
                        alert.severity
                    )}
                ">
                    ${escapeHTML(
                        alert.severity
                    )}
                </span>

            </div>

            <div>

                <strong>
                    ${escapeHTML(
                        alert.title
                    )}
                </strong>

                <p>
                    ${escapeHTML(
                        alert.indicator ||
                        "Unknown indicator"
                    )}
                </p>

            </div>

            <div>

                <span>
                    ${escapeHTML(
                        alert.threat_type ||
                        "Unknown"
                    )}
                </span>

            </div>

            <div>

                <strong>
                    Risk ${escapeHTML(
                        alert.risk_score
                    )}
                </strong>

            </div>

            <div>

                ${
                    alert.status !==
                    "Resolved"
                    ?
                    `
                    <button
                        class="secondary-btn"
                        onclick="resolveAlert(${alert.id})"
                    >
                        Resolve
                    </button>
                    `
                    :
                    `
                    <span class="resolved-label">
                        Resolved
                    </span>
                    `
                }

            </div>

        `;


        list.appendChild(item);

    });

}


async function resolveAlert(id) {

    try {

        const response =
            await fetch(
                ALERT_API +
                "/api/alerts/" +
                id,
                {

                    method: "PUT",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        status: "Resolved"
                    })

                }
            );


        const data =
            await response.json();

        if (data.success) {
            loadAlerts();
        }

    } catch (error) {

        console.error(error);

    }

}


function getSeverityClass(severity) {

    if (severity === "Critical") {
        return "severity-critical";
    }

    if (severity === "High") {
        return "severity-high";
    }

    if (severity === "Medium") {
        return "severity-medium";
    }

    return "severity-low";

}


function escapeHTML(value) {

    return String(
        value ?? ""
    )
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

}