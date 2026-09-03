const THEME_STORAGE_KEY = "cm_theme_mode";
const LOCALE_STORAGE_KEY = "cm_public_locale";
const THEME_ICON_MOON =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79Z"></path></svg>';
const THEME_ICON_SUN =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>';
const THEME_ICON_SYSTEM =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="2"></rect><path d="M8 20h8"></path><path d="M12 16v4"></path></svg>';
const THEME_I18N = {
  "zh-CN": {
    themeAuto: "跟随系统",
    themeLight: "浅色主题",
    themeDark: "深色主题",
    themeCurrentAuto: "主题：跟随系统",
    themeCurrentLight: "主题：浅色主题",
    themeCurrentDark: "主题：深色主题",
    languageCurrent: "切换语言",
  },
  "en-US": {
    themeAuto: "Follow system",
    themeLight: "Light theme",
    themeDark: "Dark theme",
    themeCurrentAuto: "Theme: follow system",
    themeCurrentLight: "Theme: light",
    themeCurrentDark: "Theme: dark",
    languageCurrent: "Switch language",
  },
};
const menuControllers = [];

function currentLocale() {
  return document.documentElement.lang === "en-US" ? "en-US" : "zh-CN";
}

function themeText(key, ...args) {
  const value = THEME_I18N[currentLocale()][key] || THEME_I18N["zh-CN"][key] || key;
  return typeof value === "function" ? value(...args) : value;
}

function normalizeThemeMode(value) {
  const mode = String(value || "").trim().toLowerCase();
  return mode === "light" || mode === "dark" ? mode : "auto";
}

function normalizeThemeLocale(value) {
  return String(value || "").trim().toLowerCase().replace("_", "-") === "en-us"
    ? "en-US"
    : "zh-CN";
}

function safeLocalStorage() {
  try {
    return window.localStorage || null;
  } catch (error) {
    return null;
  }
}

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

  const labels = {
    auto: themeText("themeCurrentAuto"),
    light: themeText("themeCurrentLight"),
    dark: themeText("themeCurrentDark"),
  };
  icon.innerHTML = mode === "auto" ? THEME_ICON_SYSTEM : mode === "light" ? THEME_ICON_SUN : THEME_ICON_MOON;
  btn.setAttribute("data-theme-mode", mode);
  btn.setAttribute("data-resolved-theme", resolvedTheme);
  btn.setAttribute("aria-label", labels[mode] || labels.auto);
  btn.setAttribute("title", labels[mode] || labels.auto);

  document.querySelectorAll("[data-theme-option]").forEach((item) => {
    const option = normalizeThemeMode(item.getAttribute("data-theme-option"));
    item.setAttribute("aria-checked", option === mode ? "true" : "false");
  });
  updateThemeMenuLabels();
}

function updateThemeMenuLabels() {
  const labels = {
    auto: themeText("themeAuto"),
    light: themeText("themeLight"),
    dark: themeText("themeDark"),
  };
  document.querySelectorAll("[data-theme-option]").forEach((item) => {
    const option = normalizeThemeMode(item.getAttribute("data-theme-option"));
    item.textContent = labels[option] || labels.auto;
  });
}

function loadThemeMode() {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    return normalizeThemeMode(raw);
  } catch (error) {
    // ignore
  }
  return "auto";
}

function saveThemeMode(mode) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, normalizeThemeMode(mode));
  } catch (error) {
    // ignore
  }
}

function closeChoiceMenus(except = null) {
  menuControllers.forEach((controller) => {
    if (controller === except) return;
    controller.toggle.setAttribute("aria-expanded", "false");
    controller.panel.hidden = true;
  });
}

function setupChoiceMenu(toggle, panel) {
  if (!toggle || !panel) return null;
  const controller = { toggle, panel };
  menuControllers.push(controller);

  toggle.addEventListener("click", (event) => {
    event.stopPropagation();
    const willOpen = panel.hidden;
    closeChoiceMenus(willOpen ? controller : null);
    panel.hidden = !willOpen;
    toggle.setAttribute("aria-expanded", willOpen ? "true" : "false");
  });

  panel.addEventListener("click", (event) => {
    event.stopPropagation();
  });

  return controller;
}

function setupThemeControls() {
  const btn = document.getElementById("theme-toggle");
  const panel = document.getElementById("theme-menu");
  if (!btn) return;

  let mode = loadThemeMode();
  let resolved = applyTheme(mode);
  updateThemeToggle(mode, resolved);
  setupChoiceMenu(btn, panel);

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

  document.querySelectorAll("[data-theme-option]").forEach((item) => {
    item.addEventListener("click", () => {
      mode = normalizeThemeMode(item.getAttribute("data-theme-option"));
      saveThemeMode(mode);
      resolved = applyTheme(mode);
      updateThemeToggle(mode, resolved);
      closeChoiceMenus();
    });
  });

  window.addEventListener("cm:localechange", () => {
    updateThemeToggle(mode, resolved);
  });
}

function loadLocalePreference() {
  const storage = safeLocalStorage();
  if (!storage) return "zh-CN";
  return normalizeThemeLocale(storage.getItem(LOCALE_STORAGE_KEY));
}

function saveLocalePreference(locale) {
  const storage = safeLocalStorage();
  if (!storage) return;
  storage.setItem(LOCALE_STORAGE_KEY, normalizeThemeLocale(locale));
}

function updateLanguageToggle(locale) {
  const current = normalizeThemeLocale(locale);
  const btn = document.getElementById("language-toggle");
  const icon = document.getElementById("language-icon");
  if (!btn || !icon) return;

  const buttonText = themeText("languageCurrent");
  btn.setAttribute("aria-label", buttonText);
  btn.setAttribute("title", buttonText);
  btn.setAttribute("data-locale", current);

  document.querySelectorAll("[data-locale-option]").forEach((item) => {
    const option = normalizeThemeLocale(item.getAttribute("data-locale-option"));
    item.setAttribute("aria-checked", option === current ? "true" : "false");
  });
}

function requestLocale(locale) {
  const next = normalizeThemeLocale(locale);
  saveLocalePreference(next);
  if (window.CyberMonitorPublic && typeof window.CyberMonitorPublic.setLocale === "function") {
    window.CyberMonitorPublic.setLocale(next);
  } else {
    document.documentElement.lang = next;
    window.dispatchEvent(new CustomEvent("cm:localechange", { detail: { locale: next } }));
  }
  updateLanguageToggle(next);
}

function setupLanguageControls() {
  const btn = document.getElementById("language-toggle");
  const panel = document.getElementById("language-menu");
  if (!btn) return;

  updateLanguageToggle(loadLocalePreference());
  setupChoiceMenu(btn, panel);

  document.querySelectorAll("[data-locale-option]").forEach((item) => {
    item.addEventListener("click", () => {
      requestLocale(item.getAttribute("data-locale-option"));
      closeChoiceMenus();
    });
  });

  window.addEventListener("cm:localechange", (event) => {
    const next = normalizeThemeLocale(event.detail && event.detail.locale);
    updateLanguageToggle(next);
    updateThemeMenuLabels();
  });
}

function setupGlobalMenuDismiss() {
  document.addEventListener("click", () => {
    closeChoiceMenus();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeChoiceMenus();
      return;
    }
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    const active = menuControllers.find((controller) => !controller.panel.hidden);
    if (!active) return;
    const items = Array.from(active.panel.querySelectorAll("button:not([disabled])"));
    if (!items.length) return;
    event.preventDefault();
    const currentIndex = items.indexOf(document.activeElement);
    const offset = event.key === "ArrowDown" ? 1 : -1;
    const nextIndex = currentIndex < 0 ? 0 : (currentIndex + offset + items.length) % items.length;
    items[nextIndex].focus();
  });
}

function setupThemeToggle() {
  setupThemeControls();
  setupLanguageControls();
  setupGlobalMenuDismiss();
}

setupThemeToggle();
