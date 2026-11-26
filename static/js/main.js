document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('input[type="file"]').forEach((input) => {
    input.addEventListener("change", () => {
      const label = input.closest(".upload-panel")?.querySelector(".selected-file");
      if (label) label.textContent = input.files?.[0]?.name || "Файл не выбран";
    });
  });
  document.querySelectorAll(".flash").forEach((item) => {
    window.setTimeout(() => item.classList.add("flash-hide"), 6000);
  });
});