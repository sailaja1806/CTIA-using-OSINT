const IOC_API =
    "http://127.0.0.1:5000";


let allIOCs = [];


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


        loadIOCs();

        document
            .getElementById(
                "iocSearch"
            )
            ?.addEventListener(
                "input",
                filterIOCs
            );


        document
            .getElementById(
                "iocFilter"
            )
            ?.addEventListener(
                "change",
                filterIOCs
            );

    }
);


async function loadIOCs() {

    try {

        const response =
            await fetch(
                IOC_API +
                "/api/iocs"
            );

        const data =
            await response.json();


        if (data.success) {

            allIOCs =
                data.iocs;

            renderIOCs(
                allIOCs
            );
        }

    } catch (error) {

        console.error(error);

    }

}


function filterIOCs() {

    const search =
        document
            .getElementById(
                "iocSearch"
            )
            .value
            .toLowerCase();


    const type =
        document
            .getElementById(
                "iocFilter"
            )
            .value;


    const filtered =
        allIOCs.filter(
            ioc => {

                const matchesSearch =
                    ioc.indicator
                        .toLowerCase()
                        .includes(search);


                const matchesType =
                    type === "All" ||
                    ioc.indicator_type ===
                    type;


                return (
                    matchesSearch &&
                    matchesType
                );

            }
        );


    renderIOCs(
        filtered
    );

}


function renderIOCs(iocs) {

    const list =
        document.getElementById(
            "iocList"
        );


    if (!iocs.length) {

        list.innerHTML = `
            <p class="empty-message">
                No matching IOCs found.
            </p>
        `;

        return;

    }


    list.innerHTML = "";


    iocs.forEach(ioc => {

        const item =
            document.createElement(
                "div"
            );

        item.className =
            "ioc-item";


        item.innerHTML = `

            <div>

                <strong>
                    ${escapeHTML(
                        ioc.indicator
                    )}
                </strong>

                <span>
                    ${escapeHTML(
                        ioc.indicator_type
                    )}
                </span>

            </div>

            <div>

                ${escapeHTML(
                    ioc.threat_type
                )}

            </div>

            <div>

                <span class="
                    severity
                    ${getSeverityClass(
                        ioc.severity
                    )}
                ">
                    ${escapeHTML(
                        ioc.severity
                    )}
                </span>

            </div>

            <div>

                Risk:
                <strong>
                    ${escapeHTML(
                        ioc.risk_score
                    )}
                </strong>

            </div>

        `;


        list.appendChild(item);

    });

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