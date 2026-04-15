const THEME_STORAGE_KEY = "cm_theme_mode";
const THEME_ICON_MOON =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79Z"></path></svg>';
const THEME_ICON_SUN =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>';

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
  icon.innerHTML = isDark ? THEME_ICON_SUN : THEME_ICON_MOON;
  btn.setAttribute("data-theme-mode", mode);
  btn.setAttribute("aria-label", isDark ? "切换到浅色模式" : "切换到深色模式");
  btn.setAttribute("title", isDark ? "切换到浅色模式" : "切换到深色模式");
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
