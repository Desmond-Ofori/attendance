function applyThemeFromStorage() {
    const themeToggle = document.getElementById("themeToggle");
    const modeBtnText = document.getElementById("mode-btn");
    const html = document.documentElement;

    if (localStorage.getItem("darkMode") === "true") {
        html.classList.add("dark-mode");
        if (themeToggle) themeToggle.querySelector("i").classList.replace("fa-moon", "fa-sun");
        if (modeBtnText) modeBtnText.textContent = "Light mode";
    } else {
        html.classList.remove("dark-mode");
        if (themeToggle) themeToggle.querySelector("i").classList.replace("fa-sun", "fa-moon");
        if (modeBtnText) modeBtnText.textContent = "Dark mode";
    }
}

document.addEventListener("DOMContentLoaded", applyThemeFromStorage);

document.addEventListener("DOMContentLoaded", function () {
    const themeToggle = document.getElementById("themeToggle");
    const modeBtnText = document.getElementById("mode-btn");
    const html = document.documentElement;

    if (themeToggle) {
        themeToggle.addEventListener("click", () => {
            html.classList.toggle("dark-mode");

            const icon = themeToggle.querySelector("i");
            const isDark = html.classList.contains("dark-mode");
            if (isDark) {
                icon.classList.replace("fa-moon", "fa-sun");
                if (modeBtnText) modeBtnText.textContent = "Light mode";
            } else {
                icon.classList.replace("fa-sun", "fa-moon");
                if (modeBtnText) modeBtnText.textContent = "Dark mode";
            }
            localStorage.setItem("darkMode", isDark ? "true" : "false");
        });
    }
});
