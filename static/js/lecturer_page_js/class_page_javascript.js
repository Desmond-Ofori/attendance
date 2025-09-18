document.addEventListener("DOMContentLoaded", function () {
    const urlParams = new URLSearchParams(window.location.search);
    let index = urlParams.get("index");

    // If no index in URL, try last saved class
    if (index === null) {
        index = localStorage.getItem("lastClassIndex");
    }

    let classes = JSON.parse(localStorage.getItem("classes")) || [];

    // If still invalid, show message
    if (!classes[index]) {
        document.body.innerHTML = "<h2>Class not found</h2>";
        return;
    }

    // Save current class as "last used"
    localStorage.setItem("lastClassIndex", index);

    const cls = classes[index];
    const classNameEl = document.getElementById("className");
    const classDetailsEl = document.getElementById("classDetails");
    if (classNameEl) classNameEl.textContent = cls.className;
    if (classDetailsEl) classDetailsEl.textContent =
        `${cls.courseName} (${cls.courseCode}) - PIN: ${cls.joinPin}`;

    // Update navigation links
    const links = {
        detailsLink: "class_page.html",
        takeAttendanceLink: "take_attendance.html",
        historyLink: "attendance_history.html",
        backBtn: "class_page.html",
        detailsLinkFooter: "class_page.html",
        takeAttendanceLinkFooter: "take_attendance.html",
        historyLinkFooter: "attendance_history.html"
    };

    Object.entries(links).forEach(([id, page]) => {
        const el = document.getElementById(id);
        if (el) el.href = `${page}?index=${index}`;
    });

    // Render attendance table
    let attendanceRecords = JSON.parse(localStorage.getItem(`attendanceRecords_${index}`)) || [];
    const table = document.getElementById("attendanceTable");
    if (table) {
        if (attendanceRecords.length === 0) {
            const row = table.insertRow(-1);
            const cell = row.insertCell(0);
            cell.colSpan = 3;
            cell.textContent = "No attendance records yet.";
            cell.style.textAlign = "center";
        } else {
            attendanceRecords.forEach(record => {
                const row = table.insertRow(-1);
                row.insertCell(0).textContent = record.date;
                row.insertCell(1).textContent = record.present.length ? record.present.join(", ") : "None";
                row.insertCell(2).textContent = record.absent.length ? record.absent.join(", ") : "None";
            });
        }
    }
});

// Sidebar toggle, submenu, and menu item activation
const toggleBtn = document.getElementById("toggleBtn");
const sidebar = document.getElementById("sidebar");
const programMenu = document.getElementById("programMenu");
const programSubmenu = document.getElementById("programSubmenu");

function loadPreferences() {
    if (localStorage.getItem("sidebarCollapsed") === "true") {
        sidebar.classList.add("collapsed");
        if (toggleBtn) toggleBtn.querySelector("i").classList.replace("fa-bars", "fa-chevron-right");
    }
}

if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
        sidebar.classList.toggle("collapsed");
        const icon = toggleBtn.querySelector("i");
        if (sidebar.classList.contains("collapsed")) {
            icon.classList.replace("fa-bars", "fa-chevron-right");
            localStorage.setItem("sidebarCollapsed", "true");
        } else {
            icon.classList.replace("fa-chevron-right", "fa-bars");
            localStorage.setItem("sidebarCollapsed", "false");
        }
    });
}

// Program submenu toggle
if (programMenu && programSubmenu) {
    programMenu.addEventListener("click", (e) => {
        e.preventDefault();
        programMenu.classList.toggle("active");
        programSubmenu.classList.toggle("active");
    });
}

// Menu item activation
const menuItems = document.querySelectorAll(".menu-item:not(.has-submenu)");
menuItems.forEach((item) => {
    item.addEventListener("click", function () {
        menuItems.forEach((i) => i.classList.remove("active"));
        this.classList.add("active");
    });
});

function checkScreenSize() {
    if (window.innerWidth <= 768 && sidebar) sidebar.classList.add("collapsed");
}

loadPreferences();
window.addEventListener("resize", checkScreenSize);
checkScreenSize();
