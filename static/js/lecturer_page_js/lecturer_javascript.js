document.addEventListener("DOMContentLoaded", async function () {
    const TOKEN = sessionStorage.getItem("tapin_token"); // Lecturer auth token
    const classList = document.getElementById("classList");

    // -----------------------------
    // API Helper Function
    // -----------------------------
    async function api(path, options = {}) {
        try {
            const res = await fetch(window.getApiUrl(path), {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...(options.headers || {}),
                    ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
                },
            });

            let data;
            try {
                data = await res.json();
            } catch (jsonErr) {
                data = { error: await res.text() || 'Invalid response format' };
            }

            if (!res.ok) {
                return { error: data.error || data.message || `HTTP ${res.status}: ${res.statusText}` };
            }

            return data;
        } catch (err) {
            console.error("API Error:", err);
            return { error: "Failed to connect to the server: " + err.message };
        }
    }

    // -----------------------------
    // Load Classes
    // -----------------------------
    async function loadClasses() {
        classList.innerHTML = `<p style="text-align:center;">Loading...</p>`;
        const res = await api("/classes");

        classList.innerHTML = "";
        if (res.error || !res.length) {
            classList.innerHTML = `<p style="text-align:center;color:#888;">No classes available.</p>`;
            return;
        }

        res.forEach((cls) => {
            const div = document.createElement("div");
            div.classList.add("class-item");
            div.innerHTML = `
                <div class="class-info" onclick="window.location.href='class_page.html?classId=${cls.id}'">
                    <h3>${cls.course_name}</h3>
                    <p>${cls.course_name} (${cls.course_code})</p>
                    <small>PIN: ${cls.join_pin}</small>
                </div>
            `;
            classList.appendChild(div);
        });
    }

    // Initial load
    if (classList) {
        await loadClasses();
    }

    // -----------------------------
    // Create Class Modal Logic
    // -----------------------------
    const classFormContainer = document.getElementById("classFormContainer");
    if (classFormContainer) {
        const form = document.getElementById("classForm");
        const closeBtn = document.getElementById("closeForm");
        const createBtn = document.getElementById("createClassBtn");
        const generatePinBtn = document.getElementById("generatePin");

        if (createBtn) {
            createBtn.addEventListener("click", () => classFormContainer.style.display = "flex");
        }

        if (closeBtn) {
            closeBtn.addEventListener("click", () => classFormContainer.style.display = "none");
        }

        if (generatePinBtn) {
            generatePinBtn.addEventListener("click", () => {
                form.joinPin.value = Math.floor(100000 + Math.random() * 900000);
            });
        }

        if (form) {
            // Create new class
            form.addEventListener("submit", async (e) => {
                e.preventDefault();
                
                // Show loading state
                const submitBtn = form.querySelector('button[type="submit"]');
                const originalText = submitBtn.textContent;
                submitBtn.disabled = true;
                submitBtn.textContent = "Creating...";
                
                const classData = {
                    programme: form.programme.value,
                    faculty: form.faculty.value,
                    department: form.department.value,
                    course_name: form.courseName.value,
                    course_code: form.courseCode.value,
                    level: form.level.value,
                    section: form.section.value,
                    join_pin: form.joinPin.value || Math.floor(100000 + Math.random() * 900000).toString(),
                    class_name: form.className.value
                };
                
                try {
                    const res = await api('/classes', {
                        method: 'POST',
                        body: JSON.stringify(classData)
                    });
                    
                    if (res && res.error) {
                        let msg = res.error;
                        if (res.status === 401) {
                            alert('Session expired. Please log in again.');
                            window.location.href = '/lecturer_login';
                            return;
                        } else if (res.status === 403) {
                            msg = `${res.error}. Please verify your email first.`;
                            alert(msg);
                            return;
                        } else if (res.status === 500 && msg.includes('class_name')) {
                            // Database schema issue - try without class_name
                            delete classData.class_name;
                            const retryRes = await api('/classes', {
                                method: 'POST',
                                body: JSON.stringify(classData)
                            });
                            
                            if (retryRes && retryRes.error) {
                                alert(`Failed to create class: ${retryRes.error}. Please try again.`);
                            } else {
                                successHandler(retryRes);
                            }
                        } else {
                            alert(`Failed to create class: ${msg}. Please try again.`);
                        }
                    } else {
                        successHandler(res);
                    }
                } catch (err) {
                    console.error('Create class error:', err);
                    alert('Network error. Please check your connection and try again.');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
                }
                
                function successHandler(res) {
                    localStorage.setItem('selectedClassId', res.id);
                    if (res.join_link) {
                        alert(`Class created successfully!\nJoin link: ${res.join_link}\nShare this with students to join the class.\nNavigating to class...`);
                    } else {
                        alert("Class created successfully!\nNavigating to class...");
                    }
                    form.reset();
                    classFormContainer.style.display = 'none';
                    window.location.href = `/lecturer/class/${res.id}`;
                }
            });
        }
    }

    // -----------------------------
    // Sidebar + Theme Toggle
    // -----------------------------
    const toggleBtn = document.getElementById("toggleBtn");
    const sidebar = document.getElementById("sidebar");

    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener("click", () => {
            sidebar.classList.toggle("collapsed");
            const icon = toggleBtn.querySelector("i");
            sidebar.classList.contains("collapsed")
                ? icon.classList.replace("fa-bars", "fa-chevron-right")
                : icon.classList.replace("fa-chevron-right", "fa-bars");
            localStorage.setItem("sidebarCollapsed", sidebar.classList.contains("collapsed"));
        });

        if (window.innerWidth <= 768 || localStorage.getItem("sidebarCollapsed") === "true") {
            sidebar.classList.add("collapsed");
        }

        window.addEventListener("resize", () => {
            if (window.innerWidth <= 768) sidebar.classList.add("collapsed");
        });
    }
});
