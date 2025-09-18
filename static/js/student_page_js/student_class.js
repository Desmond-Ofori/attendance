document.addEventListener("DOMContentLoaded", () => {
    const joinBtn = document.getElementById("joinClassBtn");
    const modal = document.getElementById("joinClassModal");
    const closeModal = document.getElementById("closeModal");
    const cancelJoin = document.getElementById("cancelJoin");
    const form = document.getElementById("classForm");
    const classList = document.getElementById("studentClasses");

    // Get token from session storage
    const TOKEN = sessionStorage.getItem('tapin_token');

    // Redirect to login if no token found
    if (!TOKEN) {
        alert("Session expired. Please log in again.");
        window.location.href = "student_login.html";
        return;
    }

    // API helper function with error handling
    async function api(path, options = {}) {
        try {
            const response = await fetch(window.getApiUrl(path), {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...(options.headers || {}),
                    ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
                },
            });
            return await response.json();
        } catch (error) {
            alert("Failed to connect to the server. Please try again later.");
            return { error: "Network error" };
        }
    }

    let classes = [];

    // Load classes from API
    async function loadClasses() {
        const res = await api('/classes');
        if (res.error) {
            alert(res.error);
            return;
        }
        classes = res;
        renderClasses();
    }

    // Render class list
    function renderClasses() {
        classList.innerHTML = "";
        if (classes.length === 0) {
            classList.innerHTML = "<p>No classes joined yet.</p>";
            return;
        }

        classes.forEach((cls, index) => {
            const div = document.createElement("div");
            div.classList.add("class-item");
            div.innerHTML = `
                <h3>${cls.course_name} (${cls.course_code})</h3>
                <p><strong>Programme:</strong> ${cls.programme}</p>
                <p><strong>Level:</strong> ${cls.level} | <strong>Section:</strong> ${cls.section}</p>
                <button class="delete-btn" title="Delete Class"><i class="fa fa-trash"></i></button>
            `;

            // Clicking enters the class detail page
            div.addEventListener("click", (e) => {
                if (e.target.closest(".delete-btn")) return;
                sessionStorage.setItem("currentClassId", classes[index].id);
                window.location.href = "student_class_detail.html";
            });

            // Delete class
            div.querySelector(".delete-btn").addEventListener("click", async (e) => {
                e.stopPropagation();
                if (confirm("Are you sure you want to remove this class?")) {
                    const res = await api(`/classes/${classes[index].id}/leave`, { method: 'DELETE' });
                    if (res.error) {
                        alert(res.error);
                    } else {
                        alert("Class removed.");
                        loadClasses();
                    }
                }
            });

            classList.appendChild(div);
        });
    }

    // Modal controls
    joinBtn.addEventListener("click", () => modal.style.display = "flex");
    closeModal.addEventListener("click", () => modal.style.display = "none");
    cancelJoin.addEventListener("click", () => modal.style.display = "none");
    window.addEventListener("click", (event) => {
        if (event.target === modal) modal.style.display = "none";
    });

    // Join class handler
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const newClass = {
            programme: document.getElementById("programme").value.trim(),
            faculty: document.getElementById("faculty").value.trim(),
            department: document.getElementById("department").value.trim(),
            courseName: document.getElementById("courseName").value.trim(),
            courseCode: document.getElementById("courseCode").value.trim(),
            level: document.getElementById("level").value.trim(),
            section: document.getElementById("section").value.trim(),
            joinPin: document.getElementById("joinPin").value.trim(),
        };

        if (!newClass.joinPin.match(/^\d{4,6}$/)) {
            alert("Invalid PIN format. Use a 4-6 digit number.");
            return;
        }

        const res = await api('/classes/join', {
            method: 'POST',
            body: JSON.stringify({ join_pin: newClass.joinPin }),
        });

        if (res.error) {
            alert(res.error);
        } else {
            alert("Class joined successfully!");
            modal.style.display = "none";
            form.reset();
            loadClasses();
        }
    });

    // Initial fetch of classes
    loadClasses();
});
