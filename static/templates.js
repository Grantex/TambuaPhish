document.addEventListener("DOMContentLoaded", () => {
  const previewButtons = document.querySelectorAll(".preview-btn");
  const editButtons = document.querySelectorAll(".edit-btn");
  const addTemplateBtn = document.getElementById("add-template-btn");

  previewButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      alert("Preview functionality coming soon!");
    });
  });

  editButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      alert("Edit functionality coming soon!");
    });
  });

  addTemplateBtn.addEventListener("click", () => {
    window.location.href = "/create_custom_template";  // <-- Adjust this route if needed
  });
});

