const API_URL =
    "http://127.0.0.1:5000";


// =========================================================
// SIGNUP
// =========================================================

const signupForm =
    document.getElementById(
        "signupForm"
    );


if (signupForm) {

    signupForm.addEventListener(
        "submit",
        async function(event) {

            event.preventDefault();


            const name =
                document.getElementById(
                    "signupName"
                ).value.trim();


            const email =
                document.getElementById(
                    "signupEmail"
                ).value.trim();


            const password =
                document.getElementById(
                    "signupPassword"
                ).value;


            if (password.length < 6) {

                alert(
                    "Password must contain at least 6 characters."
                );

                return;

            }


            try {

                const response =
                    await fetch(
                        API_URL +
                        "/api/signup",
                        {

                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    name,
                                    email,
                                    password
                                })

                        }
                    );


                const data =
                    await response.json();


                if (data.success) {

                    alert(
                        "Account created successfully!"
                    );

                    signupForm.reset();

                    window.location.href =
                        "login.html";

                } else {

                    alert(
                        data.message
                    );

                }


            } catch (error) {

                console.error(
                    error
                );

                alert(
                    "Cannot connect to Fortnet backend. Make sure Flask is running."
                );

            }

        }
    );

}


// =========================================================
// LOGIN
// =========================================================

const loginForm =
    document.getElementById(
        "loginForm"
    );


if (loginForm) {

    loginForm.addEventListener(
        "submit",
        async function(event) {

            event.preventDefault();


            const email =
                document.getElementById(
                    "loginEmail"
                ).value.trim();


            const password =
                document.getElementById(
                    "loginPassword"
                ).value;


            try {

                const response =
                    await fetch(
                        API_URL +
                        "/api/login",
                        {

                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    email,
                                    password
                                })

                        }
                    );


                const data =
                    await response.json();


                if (!data.success) {

                    alert(
                        data.message
                    );

                    return;

                }


                localStorage.setItem(
                    "fortnetLoggedIn",
                    "true"
                );


                localStorage.setItem(
                    "fortnetCurrentUser",
                    JSON.stringify(
                        data.user
                    )
                );


                window.location.href =
                    "index.html";


            } catch (error) {

                console.error(
                    error
                );

                alert(
                    "Cannot connect to Fortnet backend. Make sure Flask is running."
                );

            }

        }
    );

}


// =========================================================
// LOGOUT
// =========================================================

const logoutBtn =
    document.getElementById(
        "logoutBtn"
    );


if (logoutBtn) {

    logoutBtn.addEventListener(
        "click",
        function() {

            localStorage.removeItem(
                "fortnetLoggedIn"
            );

            localStorage.removeItem(
                "fortnetCurrentUser"
            );

            window.location.href =
                "login.html";

        }
    );

}


// =========================================================
// HTML SECURITY
// =========================================================

function escapeHTML(value) {

    return String(
        value ?? ""
    )
    .replace(
        /&/g,
        "&amp;"
    )
    .replace(
        /</g,
        "&lt;"
    )
    .replace(
        />/g,
        "&gt;"
    )
    .replace(
        /"/g,
        "&quot;"
    )
    .replace(
        /'/g,
        "&#039;"
    );

}