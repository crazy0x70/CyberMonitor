const THEME_STORAGE_KEY = "cm_theme_mode";

function getSystemTheme() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function applyTheme(mode) {
  const resolved = mode === "dark" ? "dark" : mode === "light" ? "light" : getSystemTheme();
  document.documentElement.setAttribute("data-theme", resolved);
  return resolved;
}

function updateThemeToggle(mode, resolvedTheme) {
  const icon = document.getElementById("theme-icon");
  const btn = document.getElementById("theme-toggle");
  if (!icon || !btn) return;

  const isDark = resolvedTheme === "dark";
  icon.textContent = isDark ? "🌙" : "🌞";
  btn.setAttribute("data-theme-mode", mode);
  btn.removeAttribute("title");
}

function loadThemeMode() {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    const mode = (raw || "").trim();
    if (mode === "light" || mode === "dark") {
      return mode;
    }
  } catch (error) {
    // ignore
  }
  return "auto";
}

function saveThemeMode(mode) {
  try {
    if (mode === "light" || mode === "dark") {
      localStorage.setItem(THEME_STORAGE_KEY, mode);
    } else {
      localStorage.removeItem(THEME_STORAGE_KEY);
    }
  } catch (error) {
    // ignore
  }
}

function nextThemeMode(mode) {
  return mode === "dark" ? "light" : "dark";
}

function setupThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;

  let mode = loadThemeMode();
  let resolved = applyTheme(mode);
  updateThemeToggle(mode, resolved);

  const media = window.matchMedia
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : null;

  if (media && typeof media.addEventListener === "function") {
    media.addEventListener("change", () => {
      if (mode !== "auto") return;
      resolved = applyTheme(mode);
      updateThemeToggle(mode, resolved);
    });
  } else if (media && typeof media.addListener === "function") {
    media.addListener(() => {
      if (mode !== "auto") return;
      resolved = applyTheme(mode);
      updateThemeToggle(mode, resolved);
    });
  }

  btn.addEventListener("click", () => {
    mode = nextThemeMode(mode);
    saveThemeMode(mode);
    resolved = applyTheme(mode);
    updateThemeToggle(mode, resolved);
  });
}

setupThemeToggle();
