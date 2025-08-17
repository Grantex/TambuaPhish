// Elements
const openModalBtn = document.getElementById("openModalBtn");
const closeModalBtn = document.getElementById("closeModalBtn");
const moduleModal = document.getElementById("moduleModal");
const moduleForm = document.getElementById("moduleForm");
const moduleList = document.getElementById("moduleList");
const categorySelect = document.getElementById("moduleCategory");
const customCategoryInput = document.getElementById("customCategory");

// Modal open/close
openModalBtn.addEventListener("click", () => moduleModal.style.display = "block");
closeModalBtn.addEventListener("click", () => moduleModal.style.display = "none");
window.addEventListener("click", (e) => {
    if (e.target === moduleModal) moduleModal.style.display = "none";
});

// Show custom category input
categorySelect.addEventListener("change", () => {
    customCategoryInput.style.display = categorySelect.value === "Other" ? "block" : "none";
});

// Save module (backend POST request)
moduleForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const title = document.getElementById("moduleTitle").value.trim();
    const desc = document.getElementById("moduleDescription").value.trim();
    const category = categorySelect.value === "Other" ? customCategoryInput.value.trim() : categorySelect.value;
    const format = document.getElementById("moduleFormat").value;
    const duration = document.getElementById("moduleDuration").value.trim();

    if (!title || !desc || !category || !format || !duration) return;

    try {
        const response = await fetch("/save-module", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title, description: desc, category, format, duration })
        });

        if (response.ok) {
            const data = await response.json();
            addModuleCard(data); // Append new card using server response
            moduleModal.style.display = "none";
            moduleForm.reset();
            customCategoryInput.style.display = "none";
        } else {
            console.error("Failed to save module");
        }
    } catch (err) {
        console.error("Error saving module:", err);
    }
});

// Function to add card dynamically
function addModuleCard(module) {
    const newCard = document.createElement("div");
    newCard.className = "module-card";
    newCard.dataset.category = module.category;
    newCard.dataset.format = module.format;
    newCard.innerHTML = `
        <h3>${module.title}</h3>
        <p>${module.description}</p>
        <div class="tags">
            <span>Category: ${module.category}</span>
            <span>Duration: ${module.duration} min</span>
            <span>Format: ${module.format}</span>
        </div>
        <div class="card-actions">
            <button class="secondary-btn">View</button>
            <button class="primary-btn">Assign</button>
        </div>
    `;
    moduleList.appendChild(newCard);
}

// Filters
document.getElementById("searchInput").addEventListener("input", filterModules);
document.getElementById("categoryFilter").addEventListener("change", filterModules);
document.getElementById("formatFilter").addEventListener("change", filterModules);

function filterModules() {
    const searchValue = document.getElementById("searchInput").value.toLowerCase();
    const categoryValue = document.getElementById("categoryFilter").value;
    const formatValue = document.getElementById("formatFilter").value;

    document.querySelectorAll(".module-card").forEach(card => {
        const matchesSearch = card.querySelector("h3").textContent.toLowerCase().includes(searchValue);
        const matchesCategory = !categoryValue || card.dataset.category === categoryValue;
        const matchesFormat = !formatValue || card.dataset.format === formatValue;

        card.style.display = matchesSearch && matchesCategory && matchesFormat ? "flex" : "none";
    });
}
