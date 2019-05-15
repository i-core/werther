/* vim: setl et ts=4 sts=4 sw=4 */
window.onload = function() {
    var userElem = document.querySelector(".login-form input[name='username']"),
        passElem = document.querySelector(".login-form input[name='password']"),
        remeElem = document.querySelector(".login-form input[name='remember']"),
        loginForm = document.querySelector(".login-form");

    userElem.value = sessionStorage.getItem('username');
    remeElem.checked = sessionStorage.getItem('remember');

    if (userElem.value == null || userElem.value == "") {
        userElem.focus();
    } else {
        passElem.focus();
    }

    loginForm.addEventListener("submit", function(e) {
        var msgElem = document.querySelector("p.message");

        if (userElem.value == null || userElem.value == "" ||
            passElem.value == null || passElem.value == "") {
            msgElem.innerHTML = "Username and password are required";
            e.preventDefault();
            return;
        }
        sessionStorage.setItem('username', userElem.value);
        if (remeElem.checked) {
            sessionStorage.setItem('remember', remeElem.checked);
        } else {
            sessionStorage.removeItem('remember');
        }

    }, false);
};
