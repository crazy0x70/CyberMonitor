import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

const THEME_STORAGE_KEY = "cm_theme_mode";

function resolveBootTheme() {
  const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (storedTheme === "light" || storedTheme === "dark") {
    return storedTheme;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

const bootTheme = resolveBootTheme();
document.documentElement.classList.toggle("dark", bootTheme === "dark");
document.documentElement.setAttribute("data-theme", bootTheme);
document.documentElement.style.colorScheme = bootTheme;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
