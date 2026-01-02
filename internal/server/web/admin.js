const loginPanel = document.getElementById("login-panel");
const adminShell = document.getElementById("admin-shell");
const loginForm = document.getElementById("login-form");
const loginError = document.getElementById("login-error");
const nodeList = document.getElementById("node-list");
const adminEmpty = document.getElementById("admin-empty");
const refreshBtn = document.getElementById("refresh-btn");
const logoutLink = document.getElementById("logout-link");
const adminPathInput = document.getElementById("admin-path");
const adminUserInput = document.getElementById("admin-user");
const adminPassInput = document.getElementById("admin-pass");
const agentEndpointInput = document.getElementById("agent-endpoint");
const siteTitleInput = document.getElementById("site-title");
const siteIconInput = document.getElementById("site-icon-input");
const homeTitleInput = document.getElementById("home-title");
const homeSubtitleInput = document.getElementById("home-subtitle");
const groupTree = document.getElementById("group-tree");
const addGroupBtn = document.getElementById("add-group-btn");
const saveGroupBtn = document.getElementById("save-group-btn");
const testCatalogList = document.getElementById("test-catalog-list");
const addTestBtn = document.getElementById("add-test-btn");
const saveTestsBtn = document.getElementById("save-tests-btn");
const catalogHint = document.getElementById("catalog-hint");
const groupHint = document.getElementById("group-hint");
const saveSettingsBtn = document.getElementById("save-settings-btn");
const settingsHint = document.getElementById("settings-hint");
const sideLinks = document.querySelectorAll(".side-link[data-section]");
const footerYear = document.getElementById("footer-year");
const footerCommit = document.getElementById("footer-commit");
const siteIconLink = document.getElementById("site-icon");
const brandTitle = document.querySelector(".brand-link");
const installLinux = document.getElementById("install-linux");
const installWindows = document.getElementById("install-windows");
const installTabs = document.querySelectorAll("[data-install-tab]");
const installPanes = document.querySelectorAll("[data-install-pane]");
const installCodes = document.querySelectorAll(".install-code");

const TOKEN_KEY = "cm_admin_token";

const state = {
  token: localStorage.getItem(TOKEN_KEY) || "",
  settings: {
    adminUser: "",
    groups: [],
    groupTree: [],
    testCatalog: [],
    agentEndpoint: "",
    agentToken: "",
  },
};

function setView(loggedIn) {
  if (loggedIn) {
    loginPanel.classList.add("hidden");
    adminShell.classList.remove("hidden");
    showSection("settings");
  } else {
    loginPanel.classList.remove("hidden");
    adminShell.classList.add("hidden");
  }
  if (logoutLink) {
    logoutLink.classList.toggle("hidden", !loggedIn);
  }
}

function setToken(token) {
  state.token = token;
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

function authHeaders() {
  return state.token ? { Authorization: `Bearer ${state.token}` } : {};
}

async function apiFetch(url, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  const auth = authHeaders();
  Object.assign(headers, auth);
  const resp = await fetch(url, { ...options, headers });
  if (resp.status === 401) {
    setToken("");
    setView(false);
    throw new Error("登录已失效，请重新登录");
  }
  return resp;
}

async function login(username, password) {
  loginError.textContent = "";
  const resp = await fetch("/api/v1/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!resp.ok) {
    throw new Error("用户名或密码错误");
  }
  const data = await resp.json();
  if (!data.token) {
    throw new Error("未返回 token");
  }
  setToken(data.token);
  setView(true);
  await loadSettings();
  await loadNodes();
}

async function loadSettings() {
  if (!state.token) return;
  const resp = await apiFetch("/api/v1/admin/settings");
  if (!resp.ok) {
    throw new Error(`加载设置失败: ${resp.status}`);
  }
  const data = await resp.json();
  applySettingsView(data);
}

function updateAdminBrand(settings) {
  const siteTitle = (settings.site_title || "").trim();
  const homeTitle = (settings.home_title || "").trim();
  const resolvedTitle = homeTitle || siteTitle || "CyberMonitor";
  if (brandTitle) {
    brandTitle.textContent = resolvedTitle;
  }
  document.title = `${resolvedTitle} 管理后台`;
}

function applySettingsView(data) {
  adminPathInput.value = data.admin_path || "";
  adminUserInput.value = data.admin_user || "";
  adminPassInput.value = "";
  if (typeof data.admin_user === "string") {
    state.settings.adminUser = data.admin_user;
  }
  if (typeof data.agent_endpoint === "string") {
    agentEndpointInput.value = data.agent_endpoint;
    state.settings.agentEndpoint = data.agent_endpoint;
  } else if (agentEndpointInput && !agentEndpointInput.value) {
    agentEndpointInput.value = state.settings.agentEndpoint || "";
  }
  siteTitleInput.value = data.site_title || "";
  siteIconInput.value = data.site_icon || "";
  homeTitleInput.value = data.home_title || "";
  homeSubtitleInput.value = data.home_subtitle || "";
  updateAdminBrand(data);
  if (siteIconLink) {
    if (data.site_icon) {
      siteIconLink.setAttribute("href", data.site_icon);
    } else {
      siteIconLink.removeAttribute("href");
    }
  }
  if (typeof data.agent_token === "string" && data.agent_token) {
    state.settings.agentToken = data.agent_token;
  }
  state.settings.groups = Array.isArray(data.groups) ? data.groups : [];
  state.settings.groupTree = Array.isArray(data.group_tree)
    ? data.group_tree
    : buildGroupTreeFromGroups(state.settings.groups);
  state.settings.testCatalog = Array.isArray(data.test_catalog)
    ? data.test_catalog
    : [];
  renderGroupTree(state.settings.groupTree);
  renderTestCatalog(state.settings.testCatalog);
  updateFooter(data.commit || "");
  updateInstallCommands();
}

function updateFooter(commit) {
  if (footerYear) {
    const currentYear = new Date().getFullYear();
    footerYear.textContent = `©2025-${currentYear}`;
  }
  if (footerCommit && commit) {
    footerCommit.textContent = commit;
  }
}

async function saveSettingsPayload(payload) {
  const resp = await apiFetch("/api/v1/admin/settings", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    let message = `保存设置失败: ${resp.status}`;
    try {
      const data = await resp.json();
      if (data && data.error) {
        message = data.error;
      }
    } catch (error) {
      // ignore
    }
    throw new Error(message);
  }
  const data = await resp.json();
  applySettingsView(data);
  await loadNodes();
  return data;
}

async function saveBaseSettings() {
  const payload = {};
  const path = adminPathInput.value.trim();
  const user = adminUserInput.value.trim();
  const pass = adminPassInput.value.trim();
  const agentEndpoint = agentEndpointInput.value.trim();
  const siteTitle = siteTitleInput.value.trim();
  const siteIcon = siteIconInput.value.trim();
  const homeTitle = homeTitleInput.value.trim();
  const homeSubtitle = homeSubtitleInput.value.trim();

  if (path) payload.admin_path = path;
  if (user && user !== state.settings.adminUser) payload.admin_user = user;
  if (pass) payload.admin_pass = pass;
  payload.agent_endpoint = agentEndpoint;
  payload.site_title = siteTitle;
  payload.site_icon = siteIcon;
  payload.home_title = homeTitle;
  payload.home_subtitle = homeSubtitle;
  return saveSettingsPayload(payload);
}

function updateInstallCommands() {
  const endpoint =
    (agentEndpointInput && agentEndpointInput.value.trim()) ||
    state.settings.agentEndpoint ||
    window.location.origin;
  const token = state.settings.agentToken || "<your_token>";
  const escapePwsh = (value) => String(value).replace(/'/g, "''");
  if (installLinux) {
    installLinux.textContent = `curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.sh -o /tmp/agent.sh && bash /tmp/agent.sh --server-url ${endpoint} --agent-token ${token}`;
  }
  if (installWindows) {
    const safeEndpoint = escapePwsh(endpoint);
    const safeToken = escapePwsh(token);
    installWindows.textContent = `powershell -ExecutionPolicy Bypass -Command 'iwr -UseBasicParsing https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.ps1 -OutFile "$env:TEMP\\agent.ps1"; & "$env:TEMP\\agent.ps1" -ServerUrl "${safeEndpoint}" -AgentToken "${safeToken}"'`;
  }
}

installTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const target = tab.dataset.installTab;
    installTabs.forEach((item) => item.classList.remove("active"));
    installPanes.forEach((pane) => {
      pane.classList.toggle("active", pane.dataset.installPane === target);
    });
    tab.classList.add("active");
  });
});

if (agentEndpointInput) {
  agentEndpointInput.addEventListener("input", updateInstallCommands);
}

function copyInstallCommand(element) {
  const text = element.textContent || "";
  if (!text) return;
  const onSuccess = () => {
    element.classList.add("copied");
    setTimeout(() => element.classList.remove("copied"), 1200);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(onSuccess).catch(() => {});
    return;
  }
  const helper = document.createElement("textarea");
  helper.value = text;
  helper.setAttribute("readonly", "readonly");
  helper.style.position = "absolute";
  helper.style.left = "-9999px";
  document.body.appendChild(helper);
  helper.select();
  try {
    document.execCommand("copy");
    onSuccess();
  } catch (error) {
    // ignore
  }
  document.body.removeChild(helper);
}

installCodes.forEach((code) => {
  code.addEventListener("click", () => copyInstallCommand(code));
});

async function saveGroupSettings() {
  const payload = {
    group_tree: collectGroupTree(),
  };
  return saveSettingsPayload(payload);
}

async function saveTestCatalog() {
  const payload = {
    test_catalog: collectTestCatalog(),
  };
  return saveSettingsPayload(payload);
}

async function loadNodes() {
  if (!state.token) return;
  const resp = await apiFetch("/api/v1/admin/nodes");
  if (!resp.ok) {
    throw new Error(`加载失败: ${resp.status}`);
  }
  const data = await resp.json();
  renderNodes(data.nodes || []);
}

function renderNodes(nodes) {
  nodeList.innerHTML = "";
  if (!nodes.length) {
    adminEmpty.classList.remove("hidden");
    return;
  }
  adminEmpty.classList.add("hidden");
  nodes.forEach((node) => {
    nodeList.appendChild(createNodeCard(node));
  });
}

function createNodeCard(node) {
  const stats = node.stats || {};
  const nodeID = stats.node_id || stats.node_name || "--";
  const displayName = node.alias || stats.node_alias || nodeID;
  const hostLabel =
    stats.hostname && stats.hostname !== nodeID ? stats.hostname : nodeID;
  const lastSeen = node.last_seen
    ? new Date(node.last_seen * 1000).toLocaleString()
    : "--";
  const status = node.status === "offline" ? "离线" : "在线";
  const metaParts = [];
  if (hostLabel && hostLabel !== displayName) {
    metaParts.push(escapeHtml(hostLabel));
  }
  metaParts.push(escapeHtml(stats.os || "--"));
  metaParts.push(status);
  metaParts.push(lastSeen);
  const metaText = metaParts.join(" · ");

  const card = document.createElement("details");
  card.className = "admin-card";
  card.innerHTML = `
    <summary class="admin-head">
      <div class="admin-title">
        <div class="node-name">${escapeHtml(displayName)}</div>
        <div class="admin-meta">
          ${metaText}
        </div>
      </div>
    </summary>
    <div class="admin-body">
      <div class="admin-grid">
        <label class="field">
          <span>显示昵称</span>
          <input class="input" type="text" data-field="alias" placeholder="例如：杭州节点" />
        </label>
        <label class="field">
          <span>国家/地区</span>
          <input class="input" type="text" data-field="region" placeholder="如 CN / HK / US" />
        </label>
        <label class="field">
          <span>网速(Mbps)</span>
          <input class="input" type="number" min="0" step="1" data-field="net-speed" placeholder="例如 1000" />
        </label>
        <label class="field">
          <span>硬盘类型</span>
          <input class="input" type="text" data-field="disk-type" placeholder="如 SSD / HDD / NVMe" />
        </label>
        <label class="field">
          <span>分组与标签</span>
          <details class="multi-select" data-field="group-tags">
            <summary class="select-summary" data-field="group-tags-summary">未选择</summary>
            <div class="select-panel" data-field="group-tags-panel"></div>
          </details>
        </label>
        <div class="field-row span-full">
          <label class="field field-compact">
            <span>到期时间</span>
            <input class="input" type="datetime-local" step="1" data-field="expire" />
          </label>
          <label class="field field-compact">
            <span>自动续费</span>
            <select class="input" data-field="auto-renew">
              <option value="none">none</option>
              <option value="month">每月</option>
              <option value="quarter">每季</option>
              <option value="half">每半年</option>
              <option value="year">每年</option>
            </select>
          </label>
        </div>
      </div>
      <div class="test-config">
        <div class="form-hint">选择要下发的测试节点，TCP 支持自定义间隔。</div>
        <div class="test-select-list" data-field="test-selections"></div>
        <div class="form-hint" data-field="hint"></div>
      </div>
      <div class="admin-actions">
        <button class="btn tiny" type="button" data-action="save">保存配置</button>
        <button class="btn ghost tiny" type="button" data-action="delete">删除节点</button>
      </div>
    </div>
  `;

  const aliasInput = card.querySelector('[data-field="alias"]');
  aliasInput.value = node.alias || stats.node_alias || "";

  const regionInput = card.querySelector('[data-field="region"]');
  regionInput.value = node.region || "";

  const netSpeedInput = card.querySelector('[data-field="net-speed"]');
  netSpeedInput.value = node.net_speed_mbps ? String(node.net_speed_mbps) : "";

  const diskTypeInput = card.querySelector('[data-field="disk-type"]');
  diskTypeInput.value = node.disk_type || "";

  const expireInput = card.querySelector('[data-field="expire"]');
  expireInput.value = formatLocalDateTime(node.expire_at || 0);

  const autoRenewSelect = card.querySelector('[data-field="auto-renew"]');
  autoRenewSelect.value = resolveRenewPlan(node.auto_renew, node.renew_interval_sec);

  const groupTagMenu = card.querySelector('[data-field="group-tags"]');
  const selections = resolveNodeSelections(node);
  renderGroupTagMenu(groupTagMenu, selections);

  const selectionsContainer = card.querySelector('[data-field="test-selections"]');
  const selectionMap = buildSelectionMap(node);
  renderTestSelections(selectionsContainer, selectionMap);

  card.querySelector('[data-action="save"]').addEventListener("click", async (event) => {
    event.preventDefault();
    const hint = card.querySelector('[data-field="hint"]');
    hint.textContent = "保存中...";
    try {
      await saveNode(nodeID, card);
      hint.textContent = "已保存并下发配置";
    } catch (error) {
      hint.textContent = error.message;
      hint.classList.add("error");
      setTimeout(() => hint.classList.remove("error"), 2000);
    }
  });

  card.querySelector('[data-action="delete"]').addEventListener("click", async (event) => {
    event.preventDefault();
    if (!confirm(`确认删除节点 ${nodeID} 吗？`)) {
      return;
    }
    await deleteNode(nodeID);
    await loadNodes();
  });

  return card;
}

function renderGroupTree(nodes) {
  groupTree.innerHTML = "";
  if (!nodes.length) {
    groupTree.appendChild(createGroupNode(undefined, 0));
    scheduleGroupTagResize();
    return;
  }
  nodes.forEach((node) => {
    groupTree.appendChild(createGroupNode(node, 0));
  });
  scheduleGroupTagResize();
}

function scheduleGroupTagResize() {
  requestAnimationFrame(() => {
    groupTree.querySelectorAll(".group-tag .input").forEach((input) => {
      applyTagAppearance(input.closest(".group-tag"), input);
    });
  });
}

function hashString(value) {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
  }
  return hash;
}

function tagColor(value) {
  const seed = value ? hashString(value) : Math.floor(Math.random() * 360);
  const hue = seed % 360;
  return {
    bg: `hsla(${hue}, 70%, 88%, 0.9)`,
    border: `hsla(${hue}, 70%, 70%, 0.9)`,
    text: `hsl(${hue}, 25%, 22%)`,
  };
}

let tagMeasure;

function syncTagInputSize(input) {
  const value = (input.value || "").trim();
  if (!tagMeasure) {
    tagMeasure = document.createElement("span");
    tagMeasure.style.position = "absolute";
    tagMeasure.style.visibility = "hidden";
    tagMeasure.style.whiteSpace = "pre";
    document.body.appendChild(tagMeasure);
  }
  const style = window.getComputedStyle(input);
  const fallbackFont = window.getComputedStyle(document.body).font;
  tagMeasure.style.font = style.font || fallbackFont;
  tagMeasure.style.letterSpacing = style.letterSpacing;
  tagMeasure.textContent = value || "  ";
  const width = Math.ceil(tagMeasure.getBoundingClientRect().width);
  const extra = 6;
  const targetWidth = Math.max(width + extra, 16);
  input.style.width = `${targetWidth}px`;
  input.style.minWidth = `${targetWidth}px`;
}

function applyTagAppearance(container, input) {
  const value = (input.value || "").trim();
  syncTagInputSize(input);
  if (!value) {
    input.style.background = "";
    input.style.borderColor = "";
    input.style.color = "";
    return;
  }
  const color = tagColor(value);
  input.style.background = color.bg;
  input.style.borderColor = color.border;
  input.style.color = color.text;
}

function createGroupNode(node = { name: "", children: [] }, depth = 0) {
  const container = document.createElement("div");
  container.className = depth === 0 ? "group-node" : "group-node group-tag";

  const row = document.createElement("div");
  row.className = "group-row";
  row.innerHTML = `
    <input class="input" type="text" data-field="name" placeholder="${depth === 0 ? "分组名称" : "标签名称"}" />
    ${depth === 0 ? '<button class="btn ghost tiny" type="button" data-action="add-child">添加标签</button>' : ""}
    ${
      depth === 0
        ? '<button class="btn ghost tiny" type="button" data-action="remove">移除</button>'
        : '<button class="tag-remove" type="button" data-action="remove" aria-label="删除标签">×</button>'
    }
  `;

  const nameInput = row.querySelector('[data-field="name"]');
  nameInput.value = node.name || "";
  if (depth > 0) {
    const sync = () => applyTagAppearance(container, nameInput);
    nameInput.addEventListener("input", sync);
    sync();
    requestAnimationFrame(() => applyTagAppearance(container, nameInput));
  }

  const children = document.createElement("div");
  children.className = "group-children";

  if (Array.isArray(node.children) && depth === 0) {
    node.children.forEach((child) => {
      children.appendChild(createGroupNode(child, depth + 1));
    });
  }

  const addChildBtn = row.querySelector('[data-action="add-child"]');
  if (addChildBtn) {
    addChildBtn.addEventListener("click", () => {
      children.appendChild(createGroupNode(undefined, depth + 1));
    });
  }

  row.querySelector('[data-action="remove"]').addEventListener("click", () => {
    container.remove();
  });

  container.appendChild(row);
  if (depth === 0) {
    container.appendChild(children);
  }
  return container;
}

function collectGroupTree() {
  return collectGroupNodes(groupTree);
}

function collectGroupNodes(container, depth = 0) {
  const nodes = [];
  Array.from(container.children)
    .filter((child) => child.classList.contains("group-node"))
    .forEach((nodeEl) => {
      const nameInput = nodeEl.querySelector('[data-field="name"]');
      const name = nameInput ? nameInput.value.trim() : "";
      const childrenEl = nodeEl.querySelector(".group-children");
      const children =
        depth === 0 && childrenEl ? collectGroupNodes(childrenEl, depth + 1) : [];
      if (!name) {
        return;
      }
      nodes.push({ name, children });
    });
  return nodes;
}

function flattenGroupTree(nodes, prefix = "", level = 0, result = []) {
  nodes.forEach((node) => {
    const name = (node.name || "").trim();
    if (!name) return;
    const path = prefix ? `${prefix}/${name}` : name;
    if (Array.isArray(node.children) && node.children.length > 0) {
      flattenGroupTree(node.children, path, level + 1, result);
    } else {
      result.push({ value: path, label: name, level });
    }
  });
  return result;
}

function buildGroupTreeFromGroups(groups) {
  const root = [];
  groups.forEach((group) => {
    const trimmed = String(group || "").trim();
    if (!trimmed) return;
    const parts = trimmed.split("/").map((part) => part.trim()).filter(Boolean);
    if (!parts.length) return;
    const groupName = parts[0];
    let node = root.find((item) => item.name === groupName);
    if (!node) {
      node = { name: groupName, children: [] };
      root.push(node);
    }
    if (parts.length > 1) {
      const tagName = parts.slice(1).join("/");
      if (tagName) {
        node.children = node.children || [];
        node.children.push({ name: tagName, children: [] });
      }
    }
  });
  return root;
}

function renderGroupTagMenu(container, selections) {
  if (!container) return;
  const summary = container.querySelector('[data-field="group-tags-summary"]');
  const panel = container.querySelector('[data-field="group-tags-panel"]');
  if (!summary || !panel) return;

  panel.innerHTML = "";
  const tree = state.settings.groupTree.length
    ? state.settings.groupTree
    : buildGroupTreeFromGroups(state.settings.groups);
  const groups = tree.map((node) => (node.name || "").trim()).filter(Boolean);
  const selectedSet = new Set(normalizeSelectionValues(selections));

  const updateSummary = () => {
    summary.textContent = selectedSet.size
      ? Array.from(selectedSet).join("、")
      : "未选择";
  };

  const syncGroupState = (groupName, groupInput, tagInputs, tagValues) => {
    const groupSelected = selectedSet.has(groupName);
    const tagSelected = tagValues.some((value) => selectedSet.has(value));
    groupInput.disabled = tagSelected;
    tagInputs.forEach((input) => {
      input.disabled = groupSelected;
    });
  };

  groups.forEach((group) => {
    const block = document.createElement("div");
    block.className = "group-select-block";

    const head = document.createElement("label");
    head.className = "group-select-head";
    const groupInput = document.createElement("input");
    groupInput.type = "checkbox";
    groupInput.dataset.value = group;
    groupInput.checked = selectedSet.has(group);
    const headText = document.createElement("span");
    headText.textContent = group;
    head.appendChild(groupInput);
    head.appendChild(headText);

    const tagWrap = document.createElement("div");
    tagWrap.className = "group-select-tags";
    const tagInputs = [];
    const tagValues = [];

    extractTags(tree, group).forEach((tag) => {
      const value = `${group}:${tag}`;
      const label = document.createElement("label");
      label.className = "group-select-tag";
      const input = document.createElement("input");
      input.type = "checkbox";
      input.dataset.value = value;
      input.checked = selectedSet.has(value);
      const text = document.createElement("span");
      text.textContent = tag;
      label.appendChild(input);
      label.appendChild(text);
      tagWrap.appendChild(label);
      tagInputs.push(input);
      tagValues.push(value);

      input.addEventListener("change", () => {
        if (input.checked) {
          selectedSet.add(value);
          selectedSet.delete(group);
          groupInput.checked = false;
        } else {
          selectedSet.delete(value);
        }
        syncGroupState(group, groupInput, tagInputs, tagValues);
        updateSummary();
      });
    });

    groupInput.addEventListener("change", () => {
      if (groupInput.checked) {
        selectedSet.add(group);
        tagInputs.forEach((input) => {
          selectedSet.delete(input.dataset.value || "");
          input.checked = false;
        });
      } else {
        selectedSet.delete(group);
      }
      syncGroupState(group, groupInput, tagInputs, tagValues);
      updateSummary();
    });

    syncGroupState(group, groupInput, tagInputs, tagValues);
    block.appendChild(head);
    if (tagInputs.length > 0) {
      block.appendChild(tagWrap);
    }
    panel.appendChild(block);
  });

  updateSummary();
}

function extractTags(tree, groupName) {
  if (!groupName) return [];
  const node = tree.find((item) => item && item.name === groupName);
  if (!node || !Array.isArray(node.children)) return [];
  return node.children
    .map((child) => (child.name || "").trim())
    .filter(Boolean);
}

function normalizeSelectionValues(values) {
  const result = [];
  const seen = new Set();
  const tagsByGroup = new Map();
  (values || []).forEach((value) => {
    const parsed = parseSelectionValue(value);
    if (!parsed) return;
    const key = parsed.tag ? `${parsed.group}:${parsed.tag}` : parsed.group;
    if (seen.has(key)) return;
    seen.add(key);
    if (parsed.tag) {
      if (!tagsByGroup.has(parsed.group)) {
        tagsByGroup.set(parsed.group, new Set());
      }
      tagsByGroup.get(parsed.group).add(parsed.tag);
    }
    result.push(key);
  });
  return result.filter((value) => {
    const parsed = parseSelectionValue(value);
    if (!parsed) return false;
    if (!parsed.tag && tagsByGroup.has(parsed.group)) {
      return false;
    }
    return true;
  });
}

function parseSelectionValue(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === "全部") return null;
  let group = raw;
  let tag = "";
  if (raw.includes(":")) {
    const parts = raw.split(":");
    group = (parts.shift() || "").trim();
    tag = parts.join(":").trim();
  } else if (raw.includes("/")) {
    const parts = raw.split("/");
    group = (parts.shift() || "").trim();
    tag = parts.join("/").trim();
  }
  if (!group) return null;
  return { group, tag };
}

function renderTestSelections(container, selections) {
  container.innerHTML = "";
  if (!state.settings.testCatalog.length) {
    const hint = document.createElement("div");
    hint.className = "form-hint";
    hint.textContent = "请先在后台设置测试节点";
    container.appendChild(hint);
    return;
  }
  state.settings.testCatalog.forEach((item) => {
    const isTCP = (item.type || "icmp").toLowerCase() === "tcp";
    const defaultInterval = parseInterval(item.interval_sec, 0);
    const row = document.createElement("div");
    row.className = "test-select-row";
    if (!isTCP) {
      row.classList.add("icmp");
    }
    row.dataset.id = item.id || "";
    row.dataset.type = isTCP ? "tcp" : "icmp";
    row.dataset.defaultInterval = String(defaultInterval);

    const left = document.createElement("label");
    left.className = "check";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    const selectedInterval = selections.get(item.id);
    checkbox.checked = selectedInterval !== undefined;
    const labelText = document.createElement("span");
    const typeLabel = isTCP ? "tcp" : "icmp";
    labelText.textContent = `${item.name || item.host || "未命名"}（${typeLabel}）`;
    left.appendChild(checkbox);
    left.appendChild(labelText);
    row.appendChild(left);
    const intervalInput = document.createElement("input");
    intervalInput.className = "input tiny interval-input";
    if (isTCP) {
      intervalInput.type = "number";
      intervalInput.min = "0";
      intervalInput.max = "3600";
      intervalInput.placeholder = "0 表示持续";
      intervalInput.value =
        selectedInterval !== undefined ? selectedInterval : defaultInterval;
      intervalInput.disabled = !checkbox.checked;
    } else {
      intervalInput.type = "text";
      intervalInput.value = "持续";
      intervalInput.disabled = true;
    }

    checkbox.addEventListener("change", () => {
      if (!isTCP) {
        return;
      }
      intervalInput.disabled = !checkbox.checked;
      if (checkbox.checked && intervalInput.value === "") {
        intervalInput.value = defaultInterval;
      }
    });

    row.appendChild(intervalInput);
    container.appendChild(row);
  });
}

function buildSelectionMap(node) {
  const selections = new Map();
  const catalogMeta = new Map();
  state.settings.testCatalog.forEach((item) => {
    if (!item || !item.id) return;
    const type = (item.type || "icmp").toLowerCase();
    const interval = type === "tcp" ? parseInterval(item.interval_sec, 0) : 0;
    catalogMeta.set(item.id, { type, interval });
  });
  if (Array.isArray(node.test_selections)) {
    node.test_selections.forEach((sel) => {
      if (sel && sel.test_id) {
        const meta = catalogMeta.get(sel.test_id);
        const isTCP = meta && meta.type === "tcp";
        const fallback = meta ? meta.interval : 0;
        selections.set(
          sel.test_id,
          isTCP ? resolveInterval(sel.interval_sec, fallback) : 0
        );
      }
    });
  }
  if (selections.size === 0 && Array.isArray(node.tests)) {
    const map = new Map();
    state.settings.testCatalog.forEach((item) => {
      if (item && item.id) {
        map.set(testKey(item), item.id);
      }
    });
    node.tests.forEach((test) => {
      const key = testKey(test);
      const id = map.get(key);
      if (id && !selections.has(id)) {
        const meta = catalogMeta.get(id);
        const isTCP = meta && meta.type === "tcp";
        selections.set(id, isTCP ? resolveInterval(meta.interval, 0) : 0);
      }
    });
  }
  return selections;
}

function renderTestCatalog(items) {
  testCatalogList.innerHTML = "";
  if (!Array.isArray(items) || items.length === 0) {
    testCatalogList.appendChild(createCatalogRow());
    return;
  }
  items.forEach((item) => testCatalogList.appendChild(createCatalogRow(item)));
}

function createCatalogRow(item = {}) {
  const row = document.createElement("div");
  row.className = "test-row";
  row.dataset.id = item.id || "";
  row.innerHTML = `
    <input class="input" type="text" data-field="name" placeholder="名称" />
    <select class="select" data-field="type">
      <option value="icmp">ICMP</option>
      <option value="tcp">TCP</option>
    </select>
    <input class="input" type="text" data-field="host" placeholder="域名或 IP" />
    <input class="input" type="number" min="1" max="65535" data-field="port" placeholder="端口" />
    <button class="btn ghost tiny" type="button" data-action="remove">移除</button>
  `;

  const nameInput = row.querySelector('[data-field="name"]');
  const typeSelect = row.querySelector('[data-field="type"]');
  const hostInput = row.querySelector('[data-field="host"]');
  const portInput = row.querySelector('[data-field="port"]');

  nameInput.value = item.name || "";
  nameInput.required = true;
  typeSelect.value = item.type || "icmp";
  hostInput.value = item.host || "";
  if (item.port) {
    portInput.value = item.port;
  }

  const syncTypeState = () => {
    const isICMP = typeSelect.value === "icmp";
    portInput.disabled = isICMP;
    row.classList.toggle("icmp", isICMP);
    if (isICMP) {
      portInput.value = "";
    }
  };

  typeSelect.addEventListener("change", syncTypeState);
  syncTypeState();

  row.querySelector('[data-action="remove"]').addEventListener("click", () => {
    row.remove();
  });

  return row;
}

function collectTestCatalog() {
  const rows = testCatalogList.querySelectorAll(".test-row");
  const catalog = [];
  let invalid = "";
  rows.forEach((row) => {
    const rawName = row.querySelector('[data-field="name"]').value.trim();
    const type = row.querySelector('[data-field="type"]').value;
    const rawHost = row.querySelector('[data-field="host"]').value.trim();
    let port = parseInt(row.querySelector('[data-field="port"]').value, 10);

    if (!rawName) {
      invalid = "测试节点名称不能为空";
      return;
    }
    if (hasUnsafeChars(rawName)) {
      invalid = "测试节点名称包含非法字符";
      return;
    }
    if (!rawHost) {
      invalid = "测试节点地址不能为空";
      return;
    }
    if (hasUnsafeChars(rawHost)) {
      invalid = "测试节点地址包含非法字符";
      return;
    }
    if (!isValidHost(rawHost)) {
      invalid = "测试节点地址格式不正确";
      return;
    }
    if (type === "icmp") {
      port = 0;
      if (!Number.isFinite(port)) {
        port = 0;
      }
    } else if (!Number.isFinite(port) || port <= 0) {
      invalid = "TCP 端口需为 1-65535";
      return;
    } else if (port > 65535) {
      invalid = "TCP 端口需为 1-65535";
      return;
    }
    const id = row.dataset.id || undefined;
    const name = sanitizeText(rawName);
    const host = sanitizeText(rawHost);
    catalog.push({
      id,
      name,
      type,
      host,
      port,
      interval_sec: 0,
    });
  });
  if (invalid) {
    throw new Error(invalid);
  }
  return catalog;
}

async function saveNode(nodeID, card) {
  const alias = card.querySelector('[data-field="alias"]').value.trim();
  const region = card.querySelector('[data-field="region"]').value.trim().toUpperCase();
  const netSpeedRaw = card.querySelector('[data-field="net-speed"]').value;
  const diskTypeRaw = card.querySelector('[data-field="disk-type"]').value;
  const expireRaw = card.querySelector('[data-field="expire"]').value;
  const renewPlan = card.querySelector('[data-field="auto-renew"]').value;
  const groups = collectGroupTags(card);
  const selections = collectSelections(card);

  let expireAt = 0;
  const normalizedExpire = normalizeExpireInput(expireRaw);
  if (normalizedExpire) {
    expireAt = parseLocalDateTime(normalizedExpire);
    if (!expireAt) {
      throw new Error("到期时间格式无效，请补全日期或时间");
    }
  }

  let autoRenew = renewPlan !== "none";
  let renewIntervalSec = autoRenew ? planToSeconds(renewPlan) : 0;
  if (!expireAt) {
    autoRenew = false;
    renewIntervalSec = 0;
  }

  let netSpeedMbps = parseInt(netSpeedRaw, 10);
  if (!Number.isFinite(netSpeedMbps) || netSpeedMbps < 0) {
    netSpeedMbps = 0;
  }
  const diskType = sanitizeText(diskTypeRaw);

  const payload = {
    alias,
    region,
    disk_type: diskType,
    net_speed_mbps: netSpeedMbps,
    auto_renew: autoRenew,
    groups,
    test_selections: selections,
  };
  if (normalizedExpire) {
    payload.expire_at = expireAt;
    if (autoRenew && renewIntervalSec > 0) {
      payload.renew_interval_sec = renewIntervalSec;
    }
  }

  const resp = await apiFetch(`/api/v1/admin/nodes/${encodeURIComponent(nodeID)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    throw new Error(`保存失败: ${resp.status}`);
  }
}

function collectGroupTags(card) {
  const panel = card.querySelector('[data-field="group-tags-panel"]');
  if (!panel) return [];
  const values = [];
  panel.querySelectorAll('input[type="checkbox"]:checked').forEach((input) => {
    const value = (input.dataset.value || "").trim();
    if (value) {
      values.push(value);
    }
  });
  return normalizeSelectionValues(values);
}

function collectSelections(card) {
  const selections = [];
  card.querySelectorAll(".test-select-row").forEach((row) => {
    const checkbox = row.querySelector('input[type="checkbox"]');
    if (!checkbox || !checkbox.checked) {
      return;
    }
    const id = row.dataset.id;
    if (!id) {
      return;
    }
    const isTCP = (row.dataset.type || "icmp") === "tcp";
    const fallbackInterval = parseInterval(row.dataset.defaultInterval, 0);
    let interval = 0;
    if (isTCP) {
      const intervalInput = row.querySelector('input[type="number"]');
      interval = parseInterval(intervalInput?.value, fallbackInterval);
    }
    selections.push({
      test_id: id,
      interval_sec: interval,
    });
  });
  return selections;
}

function resolveNodeSelections(node) {
  if (Array.isArray(node.groups) && node.groups.length) {
    return normalizeSelectionValues(node.groups);
  }
  const group = resolveNodeGroup(node);
  const tags = resolveNodeTags(node);
  if (!group) {
    return [];
  }
  if (tags.length) {
    return tags.map((tag) => `${group}:${tag}`);
  }
  return [group];
}

function resolveNodeGroup(node) {
  if (node.group) {
    return node.group;
  }
  if (node.stats && node.stats.node_group) {
    return node.stats.node_group;
  }
  return "";
}

function resolveNodeTags(node) {
  if (Array.isArray(node.tags) && node.tags.length) {
    return node.tags;
  }
  return [];
}

function testKey(test) {
  const type = (test.type || (test.port ? "tcp" : "icmp")).toLowerCase();
  const host = (test.host || "").trim().toLowerCase();
  const port = type === "icmp" ? 0 : Number(test.port) || 0;
  if (!host) return "";
  return `${type}|${host}|${port}`;
}

function parsePositiveNumber(value, fallback) {
  const num = parseInt(value, 10);
  if (Number.isFinite(num) && num > 0) {
    return num;
  }
  return fallback;
}

function parseInterval(value, fallback) {
  if (value === 0 || value === "0") {
    return 0;
  }
  const num = parseInt(value, 10);
  if (Number.isFinite(num) && num > 0) {
    return num;
  }
  return fallback;
}

function resolveInterval(value, fallback) {
  if (value === 0) return 0;
  const num = parseInt(value, 10);
  if (Number.isFinite(num)) {
    if (num === 0) return 0;
    if (num > 0) return num;
  }
  return fallback;
}

function formatCatalogLabel(item) {
  const type = (item.type || "icmp").toUpperCase();
  const host = item.host || "--";
  const port = item.port ? `:${item.port}` : "";
  return `${type} ${host}${port}`;
}

function formatLocalDateTime(timestamp) {
  if (!timestamp) return "";
  const date = new Date(timestamp * 1000);
  const pad = (num) => String(num).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate()
  )}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function normalizeExpireInput(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (!raw.includes("T")) {
    return `${raw}T00:00:00`;
  }
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(raw)) {
    return `${raw}:00`;
  }
  return raw;
}

function parseLocalDateTime(value) {
  const match = String(value || "").match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$/
  );
  if (!match) return 0;
  const year = Number(match[1]);
  const month = Number(match[2]) - 1;
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const date = new Date(year, month, day, hour, minute, second);
  const timestamp = date.getTime();
  if (Number.isNaN(timestamp)) return 0;
  return Math.floor(timestamp / 1000);
}

function planToSeconds(plan) {
  switch (plan) {
    case "month":
      return 30 * 86400;
    case "quarter":
      return 90 * 86400;
    case "half":
      return 180 * 86400;
    case "year":
      return 365 * 86400;
    default:
      return 0;
  }
}

function resolveRenewPlan(autoRenew, renewIntervalSec) {
  if (!autoRenew || !renewIntervalSec) return "none";
  const targets = [
    { key: "month", seconds: 30 * 86400 },
    { key: "quarter", seconds: 90 * 86400 },
    { key: "half", seconds: 180 * 86400 },
    { key: "year", seconds: 365 * 86400 },
  ];
  let best = { key: "none", diff: Infinity };
  targets.forEach((item) => {
    const diff = Math.abs(renewIntervalSec - item.seconds);
    if (diff < best.diff) {
      best = { key: item.key, diff };
    }
  });
  return best.key;
}

function flashButtonText(button, text, delay = 2000, originalText = "") {
  if (!button) return;
  const original = originalText || button.textContent;
  button.textContent = text;
  button.disabled = true;
  setTimeout(() => {
    button.textContent = original;
    button.disabled = false;
  }, delay);
}

async function deleteNode(nodeID) {
  const resp = await apiFetch(`/api/v1/admin/nodes/${encodeURIComponent(nodeID)}`, {
    method: "DELETE",
  });
  if (!resp.ok) {
    throw new Error(`删除失败: ${resp.status}`);
  }
}

async function clearNodes() {
  const resp = await apiFetch("/api/v1/admin/nodes", { method: "DELETE" });
  if (!resp.ok) {
    throw new Error(`清空失败: ${resp.status}`);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function hasUnsafeChars(value) {
  return /[<>\"'`]/.test(String(value || ""));
}

function sanitizeText(value) {
  return String(value || "").replace(/[<>\"'`]/g, "").trim();
}

function isValidHost(host) {
  const value = String(host || "").trim();
  if (!value) return false;
  if (value.includes("://") || value.includes("/") || value.includes(" ")) {
    return false;
  }
  return isValidIPv4(value) || isValidIPv6(value) || isValidHostname(value);
}

function isValidIPv4(value) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return false;
  return value.split(".").every((part) => {
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

function isValidIPv6(value) {
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(":");
}

function isValidHostname(value) {
  if (value.length > 253) return false;
  const labels = value.split(".");
  return labels.every((label) => {
    if (!label || label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
    return /^[a-zA-Z0-9-]+$/.test(label);
  });
}

function showSection(name) {
  sideLinks.forEach((link) => {
    link.classList.toggle("active", link.dataset.section === name);
  });
  document.querySelectorAll(".admin-main [data-section]").forEach((section) => {
    section.classList.toggle("hidden", section.dataset.section !== name);
  });
  if (name === "groups") {
    scheduleGroupTagResize();
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(loginForm);
  try {
    await login(formData.get("username"), formData.get("password"));
  } catch (error) {
    loginError.textContent = error.message;
  }
});

refreshBtn.addEventListener("click", () => {
  loadNodes().catch((error) => {
    alert(error.message);
  });
});

saveSettingsBtn.addEventListener("click", async () => {
  const originalText = saveSettingsBtn.textContent;
  saveSettingsBtn.textContent = "保存中...";
  saveSettingsBtn.disabled = true;
  settingsHint.textContent = "";
  settingsHint.classList.remove("error");
  try {
    await saveBaseSettings();
    flashButtonText(saveSettingsBtn, "已保存", 2000, originalText);
  } catch (error) {
    saveSettingsBtn.textContent = originalText;
    saveSettingsBtn.disabled = false;
    settingsHint.textContent = error.message;
    settingsHint.classList.add("error");
  }
});

saveGroupBtn.addEventListener("click", async () => {
  const originalText = saveGroupBtn.textContent;
  saveGroupBtn.textContent = "保存中...";
  saveGroupBtn.disabled = true;
  if (groupHint) {
    groupHint.textContent = "";
    groupHint.classList.remove("error");
  }
  try {
    await saveGroupSettings();
    flashButtonText(saveGroupBtn, "已保存", 2000, originalText);
  } catch (error) {
    saveGroupBtn.textContent = originalText;
    saveGroupBtn.disabled = false;
    if (groupHint) {
      groupHint.textContent = error.message;
      groupHint.classList.add("error");
    }
  }
});

saveTestsBtn.addEventListener("click", async () => {
  const originalText = saveTestsBtn.textContent;
  saveTestsBtn.textContent = "保存中...";
  saveTestsBtn.disabled = true;
  catalogHint.textContent = "";
  catalogHint.classList.remove("error");
  try {
    await saveTestCatalog();
    flashButtonText(saveTestsBtn, "已保存", 2000, originalText);
  } catch (error) {
    saveTestsBtn.textContent = originalText;
    saveTestsBtn.disabled = false;
    catalogHint.textContent = error.message;
    catalogHint.classList.add("error");
  }
});

if (logoutLink) {
  logoutLink.addEventListener("click", () => {
    setToken("");
    setView(false);
  });
}

addTestBtn.addEventListener("click", () => {
  testCatalogList.appendChild(createCatalogRow());
});

addGroupBtn.addEventListener("click", () => {
  groupTree.appendChild(createGroupNode(undefined, 0));
});

sideLinks.forEach((link) => {
  link.addEventListener("click", () => {
    showSection(link.dataset.section);
  });
});

updateFooter("");
setView(Boolean(state.token));
if (state.token) {
  Promise.all([loadSettings(), loadNodes()]).catch((error) => {
    loginError.textContent = error.message;
    setView(false);
  });
}
