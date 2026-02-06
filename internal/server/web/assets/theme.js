const THEME_STORAGE_KEY = "cm_theme_mode";

function getSystemTheme() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function resolveTheme(mode) {
  if (mode === "light" || mode === "dark") {
    return mode;
  }
  return getSystemTheme();
}

function applyTheme(mode) {
  const theme = resolveTheme(mode);
  document.documentElement.setAttribute("data-theme", theme);
  return theme;
}

function updateThemeToggle(mode, appliedTheme) {
  const label = document.getElementById("theme-label");
  const icon = document.getElementById("theme-icon");
  const btn = document.getElementById("theme-toggle");
  if (!label || !icon || !btn) return;

  if (mode === "light") {
    label.textContent = "浅色";
    icon.textContent = "☀";
  } else if (mode === "dark") {
    label.textContent = "深色";
    icon.textContent = "☾";
  } else {
    label.textContent = "自动";
    icon.textContent = "A";
  }
  btn.setAttribute("data-theme-mode", mode);
  btn.setAttribute("title", `当前：${label.textContent}（显示：${appliedTheme}）`);
}

function loadThemeMode() {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    const mode = (raw || "").trim();
    if (mode === "light" || mode === "dark" || mode === "auto") {
      return mode;
    }
  } catch (error) {
    // ignore
  }
  return "auto";
}

function saveThemeMode(mode) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, mode);
  } catch (error) {
    // ignore
  }
}

function nextThemeMode(mode) {
  if (mode === "auto") return "light";
  if (mode === "light") return "dark";
  return "auto";
}

function setupThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;

  let mode = loadThemeMode();
  let applied = applyTheme(mode);
  updateThemeToggle(mode, applied);

  const media = window.matchMedia
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : null;

  if (media && typeof media.addEventListener === "function") {
    media.addEventListener("change", () => {
      if (mode !== "auto") return;
      applied = applyTheme(mode);
      updateThemeToggle(mode, applied);
    });
  } else if (media && typeof media.addListener === "function") {
    media.addListener(() => {
      if (mode !== "auto") return;
      applied = applyTheme(mode);
      updateThemeToggle(mode, applied);
    });
  }

  btn.addEventListener("click", () => {
    mode = nextThemeMode(mode);
    saveThemeMode(mode);
    applied = applyTheme(mode);
    updateThemeToggle(mode, applied);
  });
}

setupThemeToggle();

