document.addEventListener("DOMContentLoaded", function () {
    const createBtn = document.getElementById("createClassBtn");
    const modal = document.getElementById("classFormContainer");
    const closeBtn = document.getElementById("closeForm");
    const form = document.getElementById("classForm");
    const classList = document.getElementById("classList");
    const generatePinBtn = document.getElementById("generatePin");

    // Open form
    createBtn.addEventListener("click", () => modal.style.display = "flex");

    // Close form
    closeBtn.addEventListener("click", () => modal.style.display = "none");

    // Generate PIN
    generatePinBtn.addEventListener("click", () => {
        form.joinPin.value = Math.floor(100000 + Math.random() * 900000);
    });

    // Load saved classes
    let classes = JSON.parse(localStorage.getItem("classes")) || [];
    displayClasses();

    // Handle form submit
    form.addEventListener("submit", function (e) {
        e.preventDefault();

        const classData = {
            course_name: form.courseName.value,
            programme: form.programme.value,
            faculty: form.faculty.value,
            department: form.department.value,
            course_name: form.courseName.value,
            courseCode: form.courseCode.value,
            level: form.level.value,
            section: form.section.value,
            joinPin: form.joinPin.value
        };

        classes.push(classData);
        localStorage.setItem("classes", JSON.stringify(classes));

        displayClasses();
        form.reset();
        modal.style.display = "none";
    });

    // Render classes with delete button
    function displayClasses() {
        classList.innerHTML = "";
        classes = JSON.parse(localStorage.getItem("classes")) || [];
        classes.forEach((cls, index) => {
            const div = document.createElement("div");
            div.classList.add("class-item");
            div.innerHTML = `
                <div class="class-info" onclick="window.location.href='class_page.html?index=${index}'">
                    <h3>${cls.course_name}</h3>
                    <p>${cls.course_name} (${cls.courseCode})</p>
                    <small>PIN: ${cls.joinPin}</small>
                </div>
                <button class="delete-btn" onclick="deleteClass(${index})">✖</button>
            `;
            classList.appendChild(div);
        });
    }

    // Delete class
    window.deleteClass = function (index) {
        let classes = JSON.parse(localStorage.getItem("classes")) || [];
        classes.splice(index, 1);
        localStorage.setItem("classes", JSON.stringify(classes));
        displayClasses();
    };

    // ==========================
    // Sidebar + Theme Logic
    // ==========================
    const toggleBtn = document.getElementById("toggleBtn");
    const sidebar = document.getElementById("sidebar");
    const themeToggle = document.getElementById("themeToggle");
    const modeBtnText = document.getElementById("mode-btn"); // ✅ Added
    const body = document.body;
    const programMenu = document.getElementById("programMenu");
    const programSubmenu = document.getElementById("programSubmenu");

    // Load saved preferences
    function loadPreferences() {
        // Sidebar state
        if (localStorage.getItem("sidebarCollapsed") === "true") {
            sidebar.classList.add("collapsed");
            toggleBtn.querySelector("i").classList.replace("fa-bars", "fa-chevron-right");
        }
    }

    // Toggle sidebar
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

    // Toggle submenu
    programMenu.addEventListener("click", (e) => {
        e.preventDefault();
        programMenu.classList.toggle("active");
        programSubmenu.classList.toggle("active");
    });

    // Set active menu item
    const menuItems = document.querySelectorAll(".menu-item:not(.has-submenu)");
    menuItems.forEach((item) => {
        item.addEventListener("click", function () {
            menuItems.forEach((i) => i.classList.remove("active"));
            this.classList.add("active");
        });
    });

    // Mobile behavior
    function checkScreenSize() {
        if (window.innerWidth <= 768) {
            sidebar.classList.add("collapsed");
        }
    }

    // Initialize
    loadPreferences();
    window.addEventListener("resize", checkScreenSize);
    checkScreenSize();
});



