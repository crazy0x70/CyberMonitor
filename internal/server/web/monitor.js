const list = document.getElementById("list");
const empty = document.getElementById("empty");
const nodeCount = document.getElementById("node-count");
const lastUpdated = document.getElementById("last-updated");
const groupTabs = document.getElementById("group-tabs");
const statTotal = document.getElementById("stat-total");
const statOnline = document.getElementById("stat-online");
const statOffline = document.getElementById("stat-offline");
const statNetUsage = document.getElementById("stat-net-usage");
const statNetRate = document.getElementById("stat-net-rate");
const brandTitle = document.getElementById("brand-title");
const brandSubtitle = document.getElementById("brand-subtitle");
const siteIcon = document.getElementById("site-icon");
const footerYear = document.getElementById("footer-year");
const footerCommit = document.getElementById("footer-commit");

const state = {
  ws: null,
  nodes: new Map(),
  reconnectTimer: null,
  selectedGroup: "全部",
  statusFilter: "all",
  lastNodes: [],
  settingsGroups: [],
  testHistory: new Map(),
  metricHistory: new Map(),
  testRange: new Map(),
  renderMode: "flat",
  tagSections: new Map(),
};

function resetToAllGroups() {
  if (state.selectedGroup === "全部") {
    return;
  }
  state.selectedGroup = "全部";
  render();
}

function setStatusFilter(mode) {
  if (state.statusFilter === mode) {
    return;
  }
  state.statusFilter = mode;
  render();
}

function connectWS() {
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${protocol}://${location.host}/ws`;
  const ws = new WebSocket(wsUrl);
  state.ws = ws;

  ws.onclose = () => {
    scheduleReconnect();
  };

  ws.onerror = () => {
    ws.close();
  };

  ws.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type === "snapshot") {
        handleSnapshot(payload);
      }
    } catch (error) {
      console.error(error);
    }
  };
}

function scheduleReconnect() {
  if (state.reconnectTimer) return;
  state.reconnectTimer = setTimeout(() => {
    state.reconnectTimer = null;
    connectWS();
  }, 2000);
}

function handleSnapshot(payload) {
  state.lastNodes = payload.nodes || [];
  state.settingsGroups = payload.groups || [];
  applyPublicSettings(payload.settings || {});
  if (lastUpdated) {
    lastUpdated.textContent = new Date(
      (payload.generated_at || 0) * 1000
    ).toLocaleTimeString();
  }
  render();
}

function render() {
  const groups = collectGroupNames(state.lastNodes, state.settingsGroups);
  renderGroupTabs(groups);
  const groupNodes = filterNodesByGroup(state.lastNodes, state.selectedGroup);
  const visibleNodes = filterNodesByStatus(groupNodes, state.statusFilter);
  if (nodeCount) {
    nodeCount.textContent = visibleNodes.length;
  }
  updateStats(groupNodes);
  updateEmptyState(visibleNodes.length, groupNodes.length);
  const mode = state.selectedGroup === "全部" ? "flat" : "tag";
  if (state.renderMode !== mode) {
    resetRenderMode(mode);
  }
  if (mode === "flat") {
    renderFlatList(visibleNodes);
  } else {
    renderTagSections(visibleNodes, state.selectedGroup);
  }
}

function updateEmptyState(visibleCount, totalCount) {
  if (visibleCount > 0) {
    empty.style.display = "none";
    return;
  }
  empty.style.display = "block";
  if (totalCount > 0 && state.selectedGroup !== "全部") {
    empty.querySelector("h2").textContent = "当前分组暂无节点";
    empty.querySelector("p").textContent = "请选择其他分组或返回全部查看。";
  } else {
    empty.querySelector("h2").textContent = "等待节点接入";
    empty.querySelector("p").textContent = "请启动 Agent 并指向当前管理端地址。";
  }
}

const RANGE_OPTIONS = [
  { key: "1h", label: "1H", seconds: 60 * 60 },
  { key: "24h", label: "24H", seconds: 60 * 60 * 24 },
  { key: "7d", label: "7D", seconds: 60 * 60 * 24 * 7 },
  { key: "30d", label: "30D", seconds: 60 * 60 * 24 * 30 },
  { key: "1y", label: "1Y", seconds: 60 * 60 * 24 * 365 },
];

function applyPublicSettings(settings) {
  if (!settings) return;
  const title = (settings.site_title || "").trim();
  const icon = (settings.site_icon || "").trim();
  const homeTitle = (settings.home_title || "").trim();
  const homeSubtitle = (settings.home_subtitle || "").trim();
  const resolvedTitle = title || "CyberMonitor";
  const resolvedHomeTitle = homeTitle || resolvedTitle;
  const resolvedSubtitle = homeSubtitle || "主机监控";
  const commit = (settings.commit || "").trim();

  if (resolvedTitle) {
    document.title = resolvedTitle;
  }
  if (brandTitle) {
    brandTitle.textContent = resolvedHomeTitle;
  }
  if (brandSubtitle) {
    brandSubtitle.textContent = resolvedSubtitle;
  }
  if (siteIcon) {
    if (icon) {
      siteIcon.setAttribute("href", icon);
    } else {
      siteIcon.removeAttribute("href");
    }
  }

  updateFooter(commit);
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

if (brandTitle) {
  brandTitle.addEventListener("click", resetToAllGroups);
}

const statTotalCard = statTotal ? statTotal.closest(".stat-card") : null;
const statOnlineCard = statOnline ? statOnline.closest(".stat-card") : null;
const statOfflineCard = statOffline ? statOffline.closest(".stat-card") : null;

if (statTotalCard) {
  statTotalCard.classList.add("clickable");
  statTotalCard.addEventListener("click", () => setStatusFilter("all"));
}
if (statOnlineCard) {
  statOnlineCard.classList.add("clickable");
  statOnlineCard.addEventListener("click", () => setStatusFilter("online"));
}
if (statOfflineCard) {
  statOfflineCard.classList.add("clickable");
  statOfflineCard.addEventListener("click", () => setStatusFilter("offline"));
}

function rangeSeconds(key) {
  const match = RANGE_OPTIONS.find((item) => item.key === key);
  return match ? match.seconds : RANGE_OPTIONS[1].seconds;
}

function collectGroupNames(nodes, settingsGroups) {
  const set = new Set();
  (settingsGroups || []).forEach((group) => set.add(group));
  nodes.forEach((node) => {
    const selections = extractGroupSelections(node);
    selections.forEach((item) => {
      if (item.group) {
        set.add(item.group);
      }
    });
  });
  return Array.from(set).filter(Boolean);
}

function extractGroupSelections(node) {
  const selections = [];
  const seen = new Set();
  const raw = Array.isArray(node.groups) ? node.groups : [];
  if (raw.length > 0) {
    raw.forEach((value) => {
      const parsed = parseGroupSelection(value);
      if (!parsed) return;
      const key = `${parsed.group}:${parsed.tag}`;
      if (seen.has(key)) return;
      seen.add(key);
      selections.push(parsed);
    });
    return selections;
  }
  const group = resolveFallbackGroup(node);
  if (group) {
    const tags = resolveFallbackTags(node);
    if (tags.length > 0) {
      tags.forEach((tag) => {
        const key = `${group}:${tag}`;
        if (seen.has(key)) return;
        seen.add(key);
        selections.push({ group, tag });
      });
    } else {
      selections.push({ group, tag: "" });
    }
  }
  return selections;
}

function parseGroupSelection(value) {
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

function resolveFallbackGroup(node) {
  if (node.group) {
    return node.group;
  }
  if (node.stats && node.stats.node_group) {
    return node.stats.node_group;
  }
  return "";
}

function resolveFallbackTags(node) {
  if (Array.isArray(node.tags) && node.tags.length > 0) {
    return normalizeTagList(node.tags);
  }
  return [];
}

function resetRenderMode(mode) {
  list.innerHTML = "";
  state.tagSections = new Map();
  state.renderMode = mode;
}

function renderGroupTabs(groups) {
  if (!groupTabs) return;
  const allGroups = ["全部", ...groups];
  if (!allGroups.includes(state.selectedGroup)) {
    state.selectedGroup = "全部";
  }
  groupTabs.innerHTML = "";
  allGroups.forEach((group) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "group-tab";
    if (group === state.selectedGroup) {
      button.classList.add("active");
    }
    button.textContent = formatGroupLabel(group);
    button.addEventListener("click", () => {
      if (state.selectedGroup === group) return;
      state.selectedGroup = group;
      render();
    });
    groupTabs.appendChild(button);
  });
}

function filterNodesByGroup(nodes, group) {
  if (!group || group === "全部") return nodes;
  return nodes.filter((node) =>
    extractGroupSelections(node).some((item) => item.group === group)
  );
}

function filterNodesByStatus(nodes, status) {
  if (status === "online") {
    return nodes.filter((node) => node.status !== "offline");
  }
  if (status === "offline") {
    return nodes.filter((node) => node.status === "offline");
  }
  return nodes;
}

function formatGroupLabel(groupPath) {
  if (!groupPath || groupPath === "全部") return "全部";
  const parts = String(groupPath).split("/").filter(Boolean);
  return parts[parts.length - 1] || groupPath;
}

function normalizeTagList(tags) {
  const seen = new Set();
  const list = [];
  (tags || []).forEach((tag) => {
    const value = String(tag || "").trim();
    if (!value || value === "全部") {
      return;
    }
    if (seen.has(value)) return;
    seen.add(value);
    list.push(value);
  });
  return list;
}

function updateStats(nodes) {
  const online = nodes.filter((node) => node.status !== "offline").length;
  const offline = nodes.length - online;
  const totalUpRate = nodes.reduce(
    (sum, node) => sum + (node.stats?.network?.tx_bytes_per_sec || 0),
    0
  );
  const totalDownRate = nodes.reduce(
    (sum, node) => sum + (node.stats?.network?.rx_bytes_per_sec || 0),
    0
  );
  const totalUp = nodes.reduce(
    (sum, node) => sum + (node.stats?.network?.bytes_sent || 0),
    0
  );
  const totalDown = nodes.reduce(
    (sum, node) => sum + (node.stats?.network?.bytes_recv || 0),
    0
  );
  statTotal.textContent = String(nodes.length);
  statOnline.textContent = String(online);
  statOffline.textContent = String(offline);
  statNetUsage.textContent = `流量 ↑ ${formatBytes(totalUp)} / ↓ ${formatBytes(
    totalDown
  )}`;
  statNetRate.textContent = `带宽 ↑ ${formatRate(totalUpRate)} / ↓ ${formatRate(
    totalDownRate
  )}`;
}

function renderFlatList(nodes) {
  const activeIds = new Set();
  nodes.forEach((node, index) => {
    const id = resolveNodeId(node, `node-flat-${index}`);
    activeIds.add(id);
    let card = state.nodes.get(id);
    if (!card) {
      card = createCard();
      state.nodes.set(id, card);
      card.classList.add("animate");
      card.addEventListener(
        "animationend",
        () => {
          card.classList.remove("animate");
        },
        { once: true }
      );
      card.style.animationDelay = `${index * 0.03}s`;
    }
    updateCard(card, node, id);
    if (card.parentElement !== list) {
      list.appendChild(card);
    }
  });
  cleanupInactive(activeIds);
}

function renderTagSections(nodes, group) {
  const activeIds = new Set();
  const activeTags = new Set();
  const sections = groupNodesByTag(nodes, group);

  sections.forEach((section, sectionIndex) => {
    const entry = ensureTagSection(section.tag, sectionIndex);
    entry.count.textContent = `(${section.nodes.length})`;
    activeTags.add(section.tag);
    section.nodes.forEach((node, index) => {
      const id = resolveNodeId(node, `node-${sectionIndex}-${index}`);
      activeIds.add(id);
      let card = state.nodes.get(id);
      if (!card) {
        card = createCard();
        state.nodes.set(id, card);
        card.classList.add("animate");
        card.addEventListener(
          "animationend",
          () => {
            card.classList.remove("animate");
          },
          { once: true }
        );
        card.style.animationDelay = `${(sectionIndex + index) * 0.03}s`;
      }
      updateCard(card, node, id);
      if (card.parentElement !== entry.list) {
        entry.list.appendChild(card);
      }
    });
    if (entry.wrapper.parentElement !== list) {
      list.appendChild(entry.wrapper);
    }
  });

  cleanupInactive(activeIds);
  cleanupTagSections(activeTags);
}

function ensureTagSection(tag, index) {
  let entry = state.tagSections.get(tag);
  if (!entry) {
    const wrapper = document.createElement("div");
    wrapper.className = "tag-section";

    const header = document.createElement("div");
    header.className = "tag-header";
    const dot = document.createElement("span");
    dot.className = "tag-dot";
    const name = document.createElement("span");
    name.className = "tag-name";
    const count = document.createElement("span");
    count.className = "tag-count";
    header.appendChild(dot);
    header.appendChild(name);
    header.appendChild(count);
    wrapper.appendChild(header);

    const list = document.createElement("div");
    list.className = "tag-list";
    wrapper.appendChild(list);

    entry = {
      wrapper,
      list,
      dot,
      name,
      count,
    };
    state.tagSections.set(tag, entry);
  }
  entry.dot.style.background = tagColor(tag, index);
  entry.name.textContent = tag;
  return entry;
}

function cleanupTagSections(activeTags) {
  for (const [tag, entry] of state.tagSections.entries()) {
    if (!activeTags.has(tag)) {
      entry.wrapper.remove();
      state.tagSections.delete(tag);
    }
  }
}

function cleanupInactive(activeIds) {
  for (const [id, card] of state.nodes.entries()) {
    if (!activeIds.has(id)) {
      card.remove();
      state.nodes.delete(id);
      state.testHistory.delete(id);
      state.testRange.delete(id);
    }
  }
}

function groupNodesByTag(nodes, group) {
  const groups = new Map();
  nodes.forEach((node) => {
    const selections = extractGroupSelections(node);
    const matches = selections.filter((item) => item.group === group);
    let primary = "未配置";
    for (const match of matches) {
      if (match.tag) {
        primary = match.tag;
        break;
      }
    }
    if (!groups.has(primary)) {
      groups.set(primary, []);
    }
    groups.get(primary).push(node);
  });
  const sorted = Array.from(groups.entries())
    .map(([tag, list]) => ({ tag, nodes: list }))
    .sort((a, b) => {
      if (a.tag === "未配置") return 1;
      if (b.tag === "未配置") return -1;
      return a.tag.localeCompare(b.tag, "zh-Hans-CN");
    });
  return sorted;
}

function resolveNodeId(node, fallback) {
  if (!node) return fallback;
  if (node.id) return String(node.id);
  const stats = node.stats || {};
  if (stats.node_id) return String(stats.node_id);
  if (stats.node_name) return String(stats.node_name);
  return fallback;
}

function createCard() {
  const card = document.createElement("details");
  card.className = "node-card";
  card.innerHTML = `
    <summary class="node-summary">
      <div class="node-summary-left">
        <div class="node-title">
          <span class="node-name" data-field="name"></span>
          <span class="status-dot" data-field="status-dot"></span>
        </div>
        <div class="node-meta">
          <span class="node-meta-text" data-field="meta"></span>
        </div>
      </div>
      <div class="node-summary-metrics">
        <div class="summary-metric">
          <div class="summary-inline">
            <span class="summary-label">CPU</span>
            <span class="summary-text" data-field="cpu-meta">--</span>
            <span class="summary-value" data-field="cpu-summary">--</span>
          </div>
          <div class="summary-bar-line">
            <div class="summary-bar">
              <span class="summary-fill cpu" data-field="cpu-mini"></span>
            </div>
          </div>
        </div>
        <div class="summary-metric">
          <div class="summary-inline">
            <span class="summary-label">内存</span>
            <span class="summary-text" data-field="mem-meta">--</span>
            <span class="summary-value" data-field="mem-summary">--</span>
          </div>
          <div class="summary-bar-line">
            <div class="summary-bar">
              <span class="summary-fill mem" data-field="mem-mini"></span>
            </div>
          </div>
        </div>
        <div class="summary-metric">
          <div class="summary-inline">
            <span class="summary-label">硬盘</span>
            <span class="summary-text" data-field="disk-meta">--</span>
            <span class="summary-value" data-field="disk-summary">--</span>
          </div>
          <div class="summary-bar-line">
            <div class="summary-bar">
              <span class="summary-fill disk" data-field="disk-mini"></span>
            </div>
          </div>
        </div>
        <div class="summary-metric">
          <div class="summary-inline">
            <span class="summary-label">网络</span>
            <span class="summary-text" data-field="net-meta">--</span>
            <span class="summary-value" data-field="net-summary">--</span>
          </div>
          <div class="summary-bar-line">
            <div class="summary-bar">
              <span class="summary-fill net" data-field="net-mini"></span>
            </div>
          </div>
        </div>
      </div>
      <div class="node-summary-right">
        <div class="summary-right-line" data-field="summary-uptime"></div>
        <div class="summary-right-line" data-field="summary-tests"></div>
      </div>
    </summary>
    <div class="node-details">
      <div class="detail-layout">
        <div class="detail-info">
          <div class="info-row"><span>状态</span><strong data-field="detail-status">--</strong></div>
          <div class="info-row"><span>运行时间</span><strong data-field="detail-uptime">--</strong></div>
          <div class="info-row"><span>剩余时间</span><strong data-field="detail-remaining">--</strong></div>
          <div class="info-row"><span>系统架构</span><strong data-field="detail-arch">--</strong></div>
          <div class="info-row"><span>内存</span><strong data-field="detail-mem">--</strong></div>
          <div class="info-row"><span>硬盘</span><strong data-field="detail-disk">--</strong></div>
          <div class="info-row"><span>地区</span><strong data-field="detail-region">--</strong></div>
          <div class="info-row"><span>系统信息</span><strong data-field="detail-os">--</strong></div>
          <div class="info-row"><span>CPU</span><strong data-field="detail-cpu">--</strong></div>
          <div class="info-row"><span>负载</span><strong data-field="detail-load">--</strong></div>
          <div class="info-row"><span>上传量</span><strong data-field="detail-upload">--</strong></div>
          <div class="info-row"><span>下载量</span><strong data-field="detail-download">--</strong></div>
          <div class="info-row"><span>首次上报</span><strong data-field="detail-first">--</strong></div>
          <div class="info-row"><span>末次上报</span><strong data-field="detail-last">--</strong></div>
        </div>
        <div class="detail-charts">
          <div class="detail-grid">
            <div class="metric">
              <div class="metric-head">
                <span>CPU</span>
                <span data-field="cpu-value">--</span>
              </div>
              <div class="meter"><span class="fill" data-field="cpu-bar"></span></div>
              <div class="metric-sub" data-field="cpu-load">Load --</div>
              <div class="metric-chart" data-field="cpu-chart"></div>
            </div>
            <div class="metric">
              <div class="metric-head">
                <span>进程</span>
                <span data-field="proc-value">--</span>
              </div>
              <div class="metric-sub" data-field="proc-detail">--</div>
              <div class="metric-chart" data-field="proc-chart"></div>
            </div>
            <div class="metric">
              <div class="metric-head">
                <span>内存</span>
                <span data-field="mem-value">--</span>
              </div>
              <div class="meter"><span class="fill mem" data-field="mem-bar"></span></div>
              <div class="metric-sub" data-field="mem-detail">--</div>
              <div class="metric-chart" data-field="mem-chart"></div>
            </div>
            <div class="metric">
              <div class="metric-head">
                <span>磁盘</span>
                <span data-field="disk-value">--</span>
              </div>
              <div class="meter"><span class="fill disk" data-field="disk-bar"></span></div>
              <div class="metric-sub" data-field="disk-detail">--</div>
              <div class="metric-chart" data-field="disk-chart"></div>
            </div>
            <div class="metric">
              <div class="metric-head">
                <span>网络</span>
                <span data-field="net-total">--</span>
              </div>
              <div class="metric-sub" data-field="net-detail">--</div>
              <div class="metric-chart" data-field="net-chart"></div>
            </div>
            <div class="metric">
              <div class="metric-head">
                <span>连接</span>
                <span data-field="conn-value">--</span>
              </div>
              <div class="metric-sub" data-field="conn-detail">--</div>
              <div class="metric-chart" data-field="conn-chart"></div>
            </div>
          </div>
        </div>
      </div>
      <div class="network-section">
        <div class="network-chart">
          <div class="network-range" data-field="test-range"></div>
          <div class="network-legend" data-field="test-legend"></div>
          <div class="network-canvas" data-field="test-chart"></div>
          <div class="network-crosshair" data-field="test-crosshair"></div>
          <div class="network-tooltip" data-field="test-tooltip"></div>
        </div>
        <div class="network-cards" data-field="test-cards"></div>
      </div>
      <div class="footer">
        <div data-field="uptime">--</div>
        <div data-field="last-seen">--</div>
      </div>
    </div>
  `;

  const fields = {
    name: card.querySelector('[data-field="name"]'),
    meta: card.querySelector('[data-field="meta"]'),
    statusDot: card.querySelector('[data-field="status-dot"]'),
    summaryUptime: card.querySelector('[data-field="summary-uptime"]'),
    summaryTests: card.querySelector('[data-field="summary-tests"]'),
    cpuSummary: card.querySelector('[data-field="cpu-summary"]'),
    memSummary: card.querySelector('[data-field="mem-summary"]'),
    diskSummary: card.querySelector('[data-field="disk-summary"]'),
    netSummary: card.querySelector('[data-field="net-summary"]'),
    cpuMini: card.querySelector('[data-field="cpu-mini"]'),
    memMini: card.querySelector('[data-field="mem-mini"]'),
    diskMini: card.querySelector('[data-field="disk-mini"]'),
    netMini: card.querySelector('[data-field="net-mini"]'),
    cpuMeta: card.querySelector('[data-field="cpu-meta"]'),
    memMeta: card.querySelector('[data-field="mem-meta"]'),
    diskMeta: card.querySelector('[data-field="disk-meta"]'),
    netMeta: card.querySelector('[data-field="net-meta"]'),
    cpuValue: card.querySelector('[data-field="cpu-value"]'),
    cpuBar: card.querySelector('[data-field="cpu-bar"]'),
    cpuLoad: card.querySelector('[data-field="cpu-load"]'),
    cpuChart: card.querySelector('[data-field="cpu-chart"]'),
    memValue: card.querySelector('[data-field="mem-value"]'),
    memBar: card.querySelector('[data-field="mem-bar"]'),
    memDetail: card.querySelector('[data-field="mem-detail"]'),
    memChart: card.querySelector('[data-field="mem-chart"]'),
    diskValue: card.querySelector('[data-field="disk-value"]'),
    diskBar: card.querySelector('[data-field="disk-bar"]'),
    diskDetail: card.querySelector('[data-field="disk-detail"]'),
    diskChart: card.querySelector('[data-field="disk-chart"]'),
    netTotal: card.querySelector('[data-field="net-total"]'),
    netDetail: card.querySelector('[data-field="net-detail"]'),
    netChart: card.querySelector('[data-field="net-chart"]'),
    procValue: card.querySelector('[data-field="proc-value"]'),
    procDetail: card.querySelector('[data-field="proc-detail"]'),
    procChart: card.querySelector('[data-field="proc-chart"]'),
    connValue: card.querySelector('[data-field="conn-value"]'),
    connDetail: card.querySelector('[data-field="conn-detail"]'),
    connChart: card.querySelector('[data-field="conn-chart"]'),
    testLegend: card.querySelector('[data-field="test-legend"]'),
    testRange: card.querySelector('[data-field="test-range"]'),
    testChart: card.querySelector('[data-field="test-chart"]'),
    testCrosshair: card.querySelector('[data-field="test-crosshair"]'),
    testTooltip: card.querySelector('[data-field="test-tooltip"]'),
    testCards: card.querySelector('[data-field="test-cards"]'),
    uptime: card.querySelector('[data-field="uptime"]'),
    lastSeen: card.querySelector('[data-field="last-seen"]'),
    detailStatus: card.querySelector('[data-field="detail-status"]'),
    detailUptime: card.querySelector('[data-field="detail-uptime"]'),
    detailArch: card.querySelector('[data-field="detail-arch"]'),
    detailOS: card.querySelector('[data-field="detail-os"]'),
    detailCPU: card.querySelector('[data-field="detail-cpu"]'),
    detailLoad: card.querySelector('[data-field="detail-load"]'),
    detailMem: card.querySelector('[data-field="detail-mem"]'),
    detailDisk: card.querySelector('[data-field="detail-disk"]'),
    detailRegion: card.querySelector('[data-field="detail-region"]'),
    detailRemaining: card.querySelector('[data-field="detail-remaining"]'),
    detailUpload: card.querySelector('[data-field="detail-upload"]'),
    detailDownload: card.querySelector('[data-field="detail-download"]'),
    detailFirst: card.querySelector('[data-field="detail-first"]'),
    detailLast: card.querySelector('[data-field="detail-last"]'),
  };

  card._fields = fields;
  return card;
}

function updateCard(card, node, nodeId) {
  const fields = card._fields;
  const stats = node.stats || {};
  const cpu = stats.cpu || {};
  const mem = stats.memory || {};
  const diskList = stats.disk || [];
  const diskIO = stats.disk_io || {};
  const net = stats.network || {};
  const tests = stats.network_tests || [];

  const displayName = resolveDisplayName(node, stats);
  const flag = flagEmoji(node.region);
  fields.name.textContent = `${flag}${displayName}`.trim();

  fields.meta.textContent = `${stats.os || "--"} · ${stats.arch || "--"}`;

  const status = node.status === "offline" ? "离线" : "在线";
  fields.statusDot.classList.toggle("offline", node.status === "offline");

  const cpuPercent = clamp(cpu.usage_percent || 0);
  fields.cpuSummary.textContent = `${cpuPercent.toFixed(0)}%`;
  if (fields.cpuMini) {
    fields.cpuMini.style.width = `${cpuPercent}%`;
  }
  fields.cpuValue.textContent = `${cpuPercent.toFixed(1)}%`;
  fields.cpuBar.style.width = `${cpuPercent}%`;
  fields.cpuLoad.textContent = `Load ${formatLoad(cpu)}`;

  const processCount = stats.process_count || 0;
  fields.procValue.textContent = `${processCount}`;
  fields.procDetail.textContent = "当前进程数";

  const memPercent = clamp(mem.used_percent || 0);
  fields.memSummary.textContent = `${memPercent.toFixed(0)}%`;
  if (fields.memMini) {
    fields.memMini.style.width = `${memPercent}%`;
  }
  fields.memValue.textContent = `${memPercent.toFixed(1)}%`;
  fields.memBar.style.width = `${memPercent}%`;
  fields.memDetail.textContent = `${formatBytes(mem.used)} / ${formatBytes(
    mem.total
  )}`;

  const diskAgg = aggregateDisk(diskList);
  const diskPercent = clamp(diskAgg.percent);
  fields.diskSummary.textContent = `${diskPercent.toFixed(0)}%`;
  if (fields.diskMini) {
    fields.diskMini.style.width = `${diskPercent}%`;
  }
  fields.diskValue.textContent = `${diskPercent.toFixed(1)}%`;
  fields.diskBar.style.width = `${diskPercent}%`;
  fields.diskDetail.textContent = `${formatBytes(diskAgg.used)} / ${formatBytes(
    diskAgg.total
  )}`;

  const netSpeed =
    Number.isFinite(node.net_speed_mbps) && node.net_speed_mbps > 0
      ? node.net_speed_mbps
      : stats.net_speed_mbps;
  const hasNetSpeed = Number.isFinite(netSpeed) && netSpeed > 0;
  const netPercent = hasNetSpeed ? calcNetPercent(net, netSpeed) : 0;
  fields.netSummary.textContent = hasNetSpeed ? `${netPercent.toFixed(0)}%` : "";
  if (fields.netMini) {
    fields.netMini.style.width = `${hasNetSpeed ? netPercent : 0}%`;
  }
  fields.cpuMeta.textContent = formatCPUModel(cpu);
  fields.memMeta.textContent = formatBytes(mem.total || 0);
  fields.diskMeta.textContent = formatDiskMeta(node, stats, diskAgg.total);
  fields.netMeta.textContent = `↑ ${formatRate(net.tx_bytes_per_sec)} · ↓ ${formatRate(
    net.rx_bytes_per_sec
  )}`;
  fields.netTotal.textContent = `↑ ${formatRate(net.tx_bytes_per_sec)} · ↓ ${formatRate(
    net.rx_bytes_per_sec
  )}`;
  fields.netDetail.textContent = `累计 ${formatBytes(net.bytes_sent)} / ${formatBytes(
    net.bytes_recv
  )}`;

  const tcpCount = stats.tcp_conns || 0;
  const udpCount = stats.udp_conns || 0;
  fields.connValue.textContent = `${tcpCount} / ${udpCount}`;
  fields.connDetail.textContent = "TCP / UDP";

  const history = updateMetricHistory(nodeId, stats, {
    cpu: cpuPercent,
    mem: mem.used || 0,
    disk: diskAgg.used || 0,
    netUp: net.tx_bytes_per_sec || 0,
    netDown: net.rx_bytes_per_sec || 0,
    process: stats.process_count || 0,
    tcp: stats.tcp_conns || 0,
    udp: stats.udp_conns || 0,
  });
  fields.cpuChart.innerHTML = renderSparklineMulti([history.cpu], ["#4f7cff"]);
  fields.procChart.innerHTML = renderSparklineMulti([history.process], ["#f97316"]);
  fields.memChart.innerHTML = renderSparklineMulti(
    [history.mem],
    ["#22c55e"],
    mem.total || 0
  );
  fields.diskChart.innerHTML = renderSparklineMulti(
    [history.disk],
    ["#f97316"],
    diskAgg.total || 0
  );
  fields.netChart.innerHTML = renderSparklineMulti(
    [history.netUp, history.netDown],
    ["#38bdf8", "#a855f7"]
  );
  fields.connChart.innerHTML = renderSparklineMulti(
    [history.tcp, history.udp],
    ["#60a5fa", "#a855f7"]
  );

  updateNetworkTests(fields, tests, nodeId);

  fields.uptime.textContent = `已运行 ${formatUptime(stats.uptime_sec || 0)}`;
  fields.lastSeen.textContent = `更新 ${formatTime(node.last_seen || 0)}`;
  fields.summaryUptime.textContent = `已运行 ${formatUptime(stats.uptime_sec || 0)}`;
  fields.summaryTests.textContent = formatRemainingSummary(
    node.expire_at || 0,
    node.auto_renew,
    node.renew_interval_sec || 0
  );

  fields.detailStatus.textContent = status;
  fields.detailUptime.textContent = formatUptime(stats.uptime_sec || 0);
  fields.detailArch.textContent = stats.arch || "--";
  fields.detailOS.textContent = stats.os || "--";
  fields.detailCPU.textContent = formatCPUModel(cpu);
  fields.detailLoad.textContent = formatLoad(cpu);
  fields.detailMem.textContent = `${formatBytes(mem.used)} / ${formatBytes(
    mem.total
  )}`;
  fields.detailDisk.textContent = `${formatBytes(diskAgg.used)} / ${formatBytes(
    diskAgg.total
  )} ${formatDiskType(node, stats)}`;
  fields.detailRegion.textContent = formatRegion(node.region);
  fields.detailRemaining.textContent = formatRemaining(
    node.expire_at || 0,
    node.auto_renew,
    node.renew_interval_sec || 0
  );
  fields.detailUpload.textContent = formatBytes(net.bytes_sent);
  fields.detailDownload.textContent = formatBytes(net.bytes_recv);
  fields.detailFirst.textContent = formatTimeFull(node.first_seen || 0);
  fields.detailLast.textContent = formatTimeFull(node.last_seen || 0);
}

function updateNetworkTests(fields, tests, nodeId) {
  if (!tests.length) {
    fields.testLegend.innerHTML = '<div class="form-hint">未配置测试</div>';
    fields.testChart.innerHTML = "";
    fields.testCards.innerHTML = "";
    if (fields.testRange) {
      fields.testRange.innerHTML = "";
    }
    if (fields.testTooltip) {
      fields.testTooltip.classList.remove("visible");
    }
    if (fields.testCrosshair) {
      fields.testCrosshair.classList.remove("visible");
    }
    return;
  }

  updateTestHistory(nodeId, tests);
  fields._tests = tests;
  renderNetworkSection(fields, nodeId);
}

function renderNetworkSection(fields, nodeId) {
  const tests = fields._tests || [];
  const historyMap = state.testHistory.get(nodeId) || new Map();
  const activeRange = state.testRange.get(nodeId) || "24h";
  renderRangeTabs(fields, nodeId, activeRange);

  fields.testLegend.innerHTML = "";
  fields.testCards.innerHTML = "";

  const seriesList = [];
  const colors = [];
  const labels = [];
  let timeSeries = [];
  const now = Math.floor(Date.now() / 1000);
  const rangeSec = rangeSeconds(activeRange);

  tests.forEach((test, index) => {
    const key = testKey(test);
    const history = historyMap.get(key) || { latency: [], loss: [], times: [] };
    const color = testColor(key, index);
    const filtered = filterHistoryByRange(history, rangeSec, now);
    if (filtered.latency.length > 0) {
      seriesList.push(filtered.latency);
      colors.push(color);
      labels.push(formatTestName(test));
      if (filtered.times.length > timeSeries.length) {
        timeSeries = filtered.times;
      }
    }

    const legend = document.createElement("div");
    legend.className = "legend-item compact";

    const dot = document.createElement("span");
    dot.className = "legend-dot";
    dot.style.background = color;

    const label = document.createElement("span");
    label.className = "legend-title";
    label.textContent = formatTestName(test);

    legend.appendChild(dot);
    legend.appendChild(label);
    fields.testLegend.appendChild(legend);

    const card = document.createElement("div");
    card.className = "network-card";

    const cardName = document.createElement("div");
    cardName.className = "network-card-name";
    cardName.textContent = formatTestName(test);

    const cardStats = document.createElement("div");
    cardStats.className = "network-card-stats";
    const stats = summarizeLatency(filtered.latency);
    const lossAvg = summarizeLoss(filtered.loss);
    cardStats.innerHTML = `
      <span>${formatLatencyStat(stats.min)}</span>
      <span>${formatLatencyStat(stats.avg)}</span>
      <span>${formatLatencyStat(stats.max)}</span>
    `;

    const loss = document.createElement("div");
    loss.className = "network-card-loss";
    loss.textContent = formatLossValue(lossAvg);

    card.appendChild(cardName);
    card.appendChild(cardStats);
    card.appendChild(loss);
    fields.testCards.appendChild(card);
  });

  const chart = buildLatencyChart(seriesList, colors, timeSeries, rangeSec);
  fields.testChart.innerHTML = chart.svg;
  setupLatencyHover(fields, chart.meta, labels);
}

function renderRangeTabs(fields, nodeId, active) {
  if (!fields.testRange) return;
  fields.testRange.innerHTML = "";
  RANGE_OPTIONS.forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "range-btn";
    if (item.key === active) {
      button.classList.add("active");
    }
    button.textContent = item.label;
    button.addEventListener("click", () => {
      if (item.key === active) return;
      state.testRange.set(nodeId, item.key);
      renderNetworkSection(fields, nodeId);
    });
    fields.testRange.appendChild(button);
  });
}

function filterHistoryByRange(history, rangeSec, nowSec) {
  if (!history) return { latency: [], loss: [], times: [] };
  const latency = Array.isArray(history.latency) ? history.latency : [];
  const loss = Array.isArray(history.loss) ? history.loss : [];
  const times = Array.isArray(history.times) ? history.times : [];
  if (!rangeSec || times.length === 0) {
    return { latency: latency.slice(), loss: loss.slice(), times: times.slice() };
  }
  const filtered = { latency: [], loss: [], times: [] };
  const minTime = nowSec - rangeSec;
  for (let i = 0; i < times.length; i += 1) {
    const ts = times[i];
    if (!ts || ts < minTime) {
      continue;
    }
    filtered.times.push(ts);
    filtered.latency.push(latency[i] ?? null);
    filtered.loss.push(loss[i] ?? null);
  }
  return filtered;
}

function buildSummaryExtra(stats, tests) {
  const parts = [`已运行 ${formatUptime(stats.uptime_sec || 0)}`];
  const summary = summarizeTests(tests, 2);
  if (summary) {
    parts.push(summary);
  }
  return parts.join(" · ");
}

function renderSummaryTests(fields, tests) {
  if (!fields.summaryTests) return;
  fields.summaryTests.innerHTML = "";
  const list = Array.isArray(tests)
    ? tests.filter((test) => test.latency_ms !== null && test.latency_ms !== undefined).slice(0, 3)
    : [];
  if (!list.length) return;
  list.forEach((test) => {
    const chip = document.createElement("div");
    chip.className = "summary-test";

    const name = document.createElement("span");
    name.className = "summary-test-name";
    name.textContent = formatTestName(test);

    const value = document.createElement("span");
    value.className = "summary-test-value";
    value.textContent = formatLatencyValue(test);

    chip.appendChild(name);
    chip.appendChild(value);
    fields.summaryTests.appendChild(chip);
  });
}

function summarizeTests(tests, limit) {
  const list = Array.isArray(tests)
    ? tests.filter((test) => test.latency_ms !== null && test.latency_ms !== undefined).slice(0, limit)
    : [];
  if (!list.length) return "";
  return list
    .map((test) => `${formatTestName(test)} ${formatLatencyValue(test)}`)
    .join(" · ");
}

function updateMetricHistory(nodeId, stats, values) {
  if (!state.metricHistory.has(nodeId)) {
    state.metricHistory.set(nodeId, {
      lastAt: 0,
      cpu: [],
      process: [],
      mem: [],
      disk: [],
      netUp: [],
      netDown: [],
      tcp: [],
      udp: [],
    });
  }
  const entry = state.metricHistory.get(nodeId);
  const timestamp = stats.timestamp || Math.floor(Date.now() / 1000);
  if (timestamp > entry.lastAt) {
    pushHistory(entry.cpu, values.cpu);
    pushHistory(entry.process, values.process);
    pushHistory(entry.mem, values.mem);
    pushHistory(entry.disk, values.disk);
    pushHistory(entry.netUp, values.netUp);
    pushHistory(entry.netDown, values.netDown);
    pushHistory(entry.tcp, values.tcp);
    pushHistory(entry.udp, values.udp);
    entry.lastAt = timestamp;
  }
  return entry;
}

function pushHistory(list, value) {
  if (!Array.isArray(list)) return;
  list.push(value);
  if (list.length > 40) {
    list.splice(0, list.length - 40);
  }
}

function updateTestHistory(nodeId, tests) {
  if (!state.testHistory.has(nodeId)) {
    state.testHistory.set(nodeId, new Map());
  }
  const map = state.testHistory.get(nodeId);
  const maxPoints = 2000;
  const maxAge = 60 * 60 * 24 * 365;
  tests.forEach((test) => {
    const key = testKey(test);
    if (!key) return;
    const entry = map.get(key) || { latency: [], loss: [], times: [], lastAt: 0 };
    const checkedAt = test.checked_at || 0;
    if (checkedAt > entry.lastAt) {
      const value =
        test.latency_ms !== null && test.latency_ms !== undefined
          ? test.latency_ms
          : null;
      let loss =
        test.packet_loss !== null && test.packet_loss !== undefined
          ? test.packet_loss
          : null;
      if (loss === null || loss === undefined || !Number.isFinite(loss)) {
        loss = value === null ? 100 : 0;
      }
      entry.latency.push(value);
      entry.loss.push(loss);
      entry.times.push(checkedAt || Math.floor(Date.now() / 1000));
      entry.lastAt = checkedAt;
      const cutoff = Math.floor(Date.now() / 1000) - maxAge;
      while (entry.times.length > 0 && entry.times[0] < cutoff) {
        entry.times.shift();
        entry.latency.shift();
        entry.loss.shift();
      }
      if (entry.latency.length > maxPoints) {
        entry.latency = entry.latency.slice(-maxPoints);
        entry.loss = entry.loss.slice(-maxPoints);
        entry.times = entry.times.slice(-maxPoints);
      }
      map.set(key, entry);
    }
  });
}

function renderSparklineMulti(seriesList, colors, maxValueOverride) {
  const width = 260;
  const height = 70;
  const normalized = seriesList
    .map((series) => (Array.isArray(series) ? series : []))
    .filter((series) => series.length > 0);
  if (!normalized.length) {
    return '<div class="sparkline-empty">--</div>';
  }
  const maxLen = Math.max(...normalized.map((series) => series.length));
  const pointsList = normalized.map((series) =>
    padSeries(series, maxLen).map((value) =>
      value === null || value === undefined ? 0 : value
    )
  );
  const flatValues = pointsList.flatMap((series) => series);
  const computedMax = Math.max(1, ...flatValues);
  const maxValue =
    Number.isFinite(maxValueOverride) && maxValueOverride > 0
      ? maxValueOverride
      : computedMax;
  const step = width / Math.max(maxLen - 1, 1);
  const lines = pointsList
    .map((series, seriesIndex) => {
      const points = series
        .map((value, index) => {
          const safeValue = Math.min(value, maxValue);
          const x = index * step;
          const y = height - (safeValue / maxValue) * height;
          return `${x.toFixed(1)},${y.toFixed(1)}`;
        })
        .join(" ");
      const color = colors[seriesIndex] || "#4f7cff";
      return `<polyline fill="none" stroke="${color}" stroke-width="2" points="${points}" />`;
    })
    .join("");
  return `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      ${lines}
    </svg>
  `;
}

function buildLatencyChart(seriesList, colors, times, rangeSec) {
  const width = 680;
  const height = 220;
  const padding = { top: 28, right: 20, bottom: 32, left: 44 };
  const normalized = seriesList
    .map((series) => (Array.isArray(series) ? series : []))
    .filter((series) => series.length > 0);
  if (!normalized.length) {
    return { svg: '<div class="sparkline-empty">--</div>', meta: null };
  }

  const maxLen = Math.max(...normalized.map((series) => series.length));
  const paddedSeries = normalized.map((series) => padSeries(series, maxLen));
  const paddedTimes = padSeries(Array.isArray(times) ? times : [], maxLen);
  const flatValues = paddedSeries
    .flatMap((series) => series)
    .filter((value) => value !== null && value !== undefined && Number.isFinite(value));
  const rawMax = flatValues.length ? Math.max(...flatValues) : 1;
  const paddedMax = rawMax * 1.1;
  const stepValue = niceStep(paddedMax / 4 || 1);
  const maxValue = Math.max(stepValue * 4, paddedMax, 1);

  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const stepX = plotWidth / Math.max(maxLen - 1, 1);

  const gridLines = [];
  const yLabels = [];
  for (let i = 0; i <= 4; i += 1) {
    const value = stepValue * i;
    const y = padding.top + plotHeight - (value / maxValue) * plotHeight;
    gridLines.push(
      `<line x1="${padding.left}" x2="${width - padding.right}" y1="${y.toFixed(
        1
      )}" y2="${y.toFixed(1)}" />`
    );
    yLabels.push(
      `<text x="${padding.left - 8}" y="${y.toFixed(
        1
      )}" text-anchor="end" dominant-baseline="middle">${formatLatencyTick(
        value
      )}</text>`
    );
  }

  const timeLabels = buildTimeLabels(paddedTimes, maxLen, 12, rangeSec);
  const xLabels = timeLabels
    .map((tick) => {
      const x = padding.left + tick.index * stepX;
      return `<text x="${x.toFixed(
        1
      )}" y="${height - 8}" text-anchor="middle">${tick.label}</text>`;
    })
    .join("");

  const lines = paddedSeries
    .map((series, idx) => {
      const path = buildLinePath(series, stepX, padding, plotHeight, maxValue);
      if (!path) return "";
      const color = colors[idx] || "#4f7cff";
      return `<path d="${path}" fill="none" stroke="${color}" stroke-width="2.2" />`;
    })
    .join("");

  const svg = `
    <svg class="latency-chart-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      <g class="latency-grid">${gridLines.join("")}</g>
      <g class="latency-axis">${yLabels.join("")}${xLabels}</g>
      <g class="latency-lines">${lines}</g>
    </svg>
  `;
  return {
    svg,
    meta: {
      maxLen,
      paddedSeries,
      paddedTimes,
      padding,
      plotWidth,
      plotHeight,
      colors: colors.slice(),
    },
  };
}

function setupLatencyHover(fields, meta, labels) {
  const container = fields.testChart;
  const tooltip = fields.testTooltip;
  const crosshair = fields.testCrosshair;
  if (!container || !tooltip || !crosshair) return;
  if (!meta || !meta.maxLen || !meta.paddedTimes.length) {
    tooltip.classList.remove("visible");
    crosshair.classList.remove("visible");
    return;
  }
  const svg = container.querySelector("svg");
  if (!svg) return;

  const hide = () => {
    tooltip.classList.remove("visible");
    crosshair.classList.remove("visible");
  };

  container.onmouseleave = hide;
  container.onmousemove = (event) => {
    const rect = svg.getBoundingClientRect();
    const hostRect = fields.testChart.parentElement.getBoundingClientRect();
    const offsetX = rect.left - hostRect.left;
    const scaleX = rect.width / 680;
    const paddingLeft = meta.padding.left * scaleX;
    const paddingRight = meta.padding.right * scaleX;
    const plotWidth = rect.width - paddingLeft - paddingRight;
    const x = event.clientX - rect.left;
    if (x < paddingLeft || x > rect.width - paddingRight) {
      hide();
      return;
    }
    const stepX = plotWidth / Math.max(meta.maxLen - 1, 1);
    const index = Math.max(
      0,
      Math.min(meta.maxLen - 1, Math.round((x - paddingLeft) / stepX))
    );
    const time = meta.paddedTimes[index];
    if (!time) {
      hide();
      return;
    }

    const rows = meta.paddedSeries
      .map((series, idx) => {
        const value = series[index];
        if (value === null || value === undefined) return "";
        const color = meta.colors[idx] || "#4f7cff";
        const name = labels[idx] || "未命名";
        return `
          <div class="latency-tooltip-row">
            <span class="latency-tooltip-dot" style="background:${color}"></span>
            <span class="latency-tooltip-name">${name}</span>
            <strong>${formatLatencyStat(value)}</strong>
          </div>
        `;
      })
      .filter(Boolean)
      .join("");

    if (!rows) {
      hide();
      return;
    }

    tooltip.innerHTML = `
      <div class="latency-tooltip-time">${formatTimeFull(time)}</div>
      ${rows}
    `;
    tooltip.classList.add("visible");

    const containerRect = hostRect;
    const tooltipRect = tooltip.getBoundingClientRect();
    let left = event.clientX - containerRect.left + 12;
    let top = event.clientY - containerRect.top + 12;
    if (left + tooltipRect.width > containerRect.width) {
      left = containerRect.width - tooltipRect.width - 12;
    }
    if (top + tooltipRect.height > containerRect.height) {
      top = containerRect.height - tooltipRect.height - 12;
    }
    tooltip.style.left = `${Math.max(left, 8)}px`;
    tooltip.style.top = `${Math.max(top, 8)}px`;

    const crossX = offsetX + paddingLeft + index * stepX;
    crosshair.style.left = `${crossX}px`;
    crosshair.classList.add("visible");
  };
}

function buildLinePath(series, stepX, padding, plotHeight, maxValue) {
  let path = "";
  let started = false;
  series.forEach((value, index) => {
    if (value === null || value === undefined) {
      started = false;
      return;
    }
    const clamped = Math.max(0, Math.min(maxValue, value));
    const x = padding.left + index * stepX;
    const y = padding.top + plotHeight - (clamped / maxValue) * plotHeight;
    if (!started) {
      path += `M${x.toFixed(1)},${y.toFixed(1)}`;
      started = true;
    } else {
      path += ` L${x.toFixed(1)},${y.toFixed(1)}`;
    }
  });
  return path;
}

function padSeries(series, length) {
  if (series.length >= length) {
    return series.slice(-length);
  }
  const padding = Array.from({ length: length - series.length }, () => null);
  return padding.concat(series);
}

function buildTimeLabels(times, maxLen, count, rangeSec) {
  if (!Array.isArray(times) || times.length === 0) {
    return [];
  }
  if (!maxLen || maxLen < 2) {
    return [];
  }
  const valid = times.filter(
    (value) => value !== null && value !== undefined && Number.isFinite(value)
  );
  const now = Math.floor(Date.now() / 1000);
  const end = valid.length ? valid[valid.length - 1] : now;
  const fallbackRange = rangeSec && rangeSec > 0 ? rangeSec : 3600;
  const start = rangeSec && rangeSec > 0 ? end - rangeSec : (valid.length ? valid[0] : end - fallbackRange);
  const safeCount = Math.max(count, 2);
  const steps = Math.max(safeCount - 1, 1);
  const labels = [];
  for (let i = 0; i < safeCount; i += 1) {
    const ratio = steps === 0 ? 0 : i / steps;
    const index = ratio * (maxLen - 1);
    const ts = start + (end - start) * ratio;
    labels.push({ index, label: formatTimeLabel(ts, rangeSec) });
  }
  return labels;
}

function niceStep(value) {
  if (!value || !Number.isFinite(value)) {
    return 1;
  }
  const pow = Math.pow(10, Math.floor(Math.log10(value)));
  const fraction = value / pow;
  let niceFraction = 1;
  if (fraction <= 1) niceFraction = 1;
  else if (fraction <= 2) niceFraction = 2;
  else if (fraction <= 5) niceFraction = 5;
  else niceFraction = 10;
  return niceFraction * pow;
}

function formatTimeLabel(timestamp, rangeSec) {
  if (!timestamp) return "";
  const date = new Date(timestamp * 1000);
  const pad = (num) => String(num).padStart(2, "0");
  if (!rangeSec || rangeSec <= 86400) {
    return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }
  if (rangeSec <= 86400 * 30) {
    return `${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  }
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}`;
}

function formatTimeFull(timestamp) {
  if (!timestamp) return "--";
  const date = new Date(timestamp * 1000);
  const pad = (num) => String(num).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate()
  )} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function formatLatencyTick(value) {
  if (value >= 100) return `${Math.round(value)}ms`;
  if (value >= 10) return `${value.toFixed(0)}ms`;
  return `${value.toFixed(1)}ms`;
}

function summarizeLatency(series) {
  const values = (Array.isArray(series) ? series : []).filter(
    (value) => value !== null && value !== undefined && Number.isFinite(value)
  );
  if (!values.length) {
    return { min: null, avg: null, max: null };
  }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const avg = values.reduce((sum, value) => sum + value, 0) / values.length;
  return { min, avg, max };
}

function summarizeLoss(series) {
  const values = (Array.isArray(series) ? series : []).filter(
    (value) => value !== null && value !== undefined && Number.isFinite(value)
  );
  if (!values.length) {
    return null;
  }
  const avg = values.reduce((sum, value) => sum + value, 0) / values.length;
  return avg;
}

function formatLatencyStat(value) {
  if (value === null || value === undefined) {
    return "--";
  }
  return `${value.toFixed(1)} ms`;
}

function formatLossValue(loss) {
  if (loss === null || loss === undefined || !Number.isFinite(loss)) {
    return "丢包 --";
  }
  return `丢包 ${loss.toFixed(1)}%`;
}

function formatCPUModel(cpu) {
  if (!cpu) return "--";
  const model = (cpu.model || "").trim();
  const cores = cpu.cores || 0;
  const parts = [];
  if (model) parts.push(model);
  if (cores) parts.push(`${cores} 核`);
  return parts.length ? parts.join(" · ") : "--";
}

function formatDiskType(node, stats) {
  const raw = (node?.disk_type || stats?.disk_type || "").trim();
  return raw || "未知";
}

function formatDiskMeta(node, stats, total) {
  const typeLabel = formatDiskType(node, stats);
  if (Number.isFinite(total) && total > 0) {
    return `${typeLabel} · ${formatBytes(total)} total`;
  }
  return typeLabel;
}

function calcNetPercent(net, speedMbps) {
  const maxMbps = Number(speedMbps || 0);
  if (!maxMbps || maxMbps <= 0) {
    return 0;
  }
  const totalMbps = ((net?.tx_bytes_per_sec || 0) + (net?.rx_bytes_per_sec || 0)) * 8 / 1_000_000;
  return clamp((totalMbps / maxMbps) * 100);
}

function formatTestName(test) {
  const name = (test.name || "").trim();
  if (name) return name;
  return "未命名";
}

function formatLatencyValue(test) {
  if (test.latency_ms !== null && test.latency_ms !== undefined) {
    return `${test.latency_ms.toFixed(1)} ms`;
  }
  return "--";
}

function testKey(test) {
  const type = (test.type || "icmp").toLowerCase();
  const host = (test.host || "").toLowerCase();
  const port = test.port || 0;
  const name = (test.name || "").toLowerCase();
  return `${type}|${host}|${port}|${name}`;
}

function testColor(key, index) {
  const palette = ["#4f7cff", "#22c55e", "#f97316", "#a855f7", "#facc15", "#14b8a6"];
  if (!key) {
    return palette[index % palette.length];
  }
  let hash = 0;
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
  }
  return palette[hash % palette.length];
}

function tagColor(tag, index) {
  return testColor(tag, index);
}

function flagEmoji(code) {
  const normalized = (code || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(normalized)) {
    return "";
  }
  const base = 0x1f1e6;
  const first = base + normalized.charCodeAt(0) - 65;
  const second = base + normalized.charCodeAt(1) - 65;
  return String.fromCodePoint(first, second) + " ";
}

function formatRegion(code) {
  const normalized = (code || "").trim().toUpperCase();
  if (!normalized) return "--";
  return `${flagEmoji(normalized)}${normalized}`.trim();
}

function formatRemaining(expireAt, autoRenew, renewIntervalSec) {
  if (!expireAt) {
    return "未设置";
  }
  const now = Math.floor(Date.now() / 1000);
  const diff = expireAt - now;
  if (diff <= 0) {
    if (autoRenew && renewIntervalSec > 0) {
      const elapsed = now - expireAt;
      const remain = renewIntervalSec - (elapsed % renewIntervalSec);
      return formatDuration(remain);
    }
    return autoRenew ? "续费中" : "已到期";
  }
  const days = Math.floor(diff / 86400);
  const hours = Math.floor((diff % 86400) / 3600);
  const minutes = Math.floor((diff % 3600) / 60);
  if (days > 0) return `${days}天 ${hours}小时`;
  if (hours > 0) return `${hours}小时 ${minutes}分钟`;
  return `${minutes}分钟`;
}

function formatRemainingSummary(expireAt, autoRenew, renewIntervalSec) {
  if (!expireAt) {
    return "--";
  }
  const value = formatRemaining(expireAt, autoRenew, renewIntervalSec);
  if (value === "未设置") {
    return "--";
  }
  if (value === "已到期" || value === "续费中") {
    return value;
  }
  return `剩余 ${value}`;
}

function formatDuration(seconds) {
  const safe = Math.max(0, Math.floor(seconds || 0));
  const days = Math.floor(safe / 86400);
  const hours = Math.floor((safe % 86400) / 3600);
  const minutes = Math.floor((safe % 3600) / 60);
  if (days > 0) return `${days}天 ${hours}小时`;
  if (hours > 0) return `${hours}小时 ${minutes}分钟`;
  return `${minutes}分钟`;
}

function resolveDisplayName(node, stats) {
  const alias = node.alias || stats.node_alias;
  if (alias) return alias;
  const hostname = (stats.hostname || "").trim();
  const nodeName = (stats.node_name || "").trim();
  if (nodeName && nodeName !== hostname) {
    return nodeName;
  }
  const nodeID = (stats.node_id || "").trim();
  if (nodeID && nodeID !== hostname) {
    return nodeID;
  }
  return "未命名节点";
}

function clamp(value) {
  if (Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(100, value));
}

function formatLoad(cpu) {
  const l1 = cpu.load1 ?? 0;
  const l5 = cpu.load5 ?? 0;
  const l15 = cpu.load15 ?? 0;
  return `${l1.toFixed(2)} / ${l5.toFixed(2)} / ${l15.toFixed(2)}`;
}

function formatBytes(bytes = 0) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Number(bytes);
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[index]}`;
}

function formatRate(bytes = 0) {
  return `${formatBytes(bytes)}/s`;
}

function formatTime(timestamp) {
  if (!timestamp) return "--";
  return new Date(timestamp * 1000).toLocaleTimeString();
}

function formatUptime(seconds = 0) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function aggregateDisk(list) {
  let total = 0;
  let used = 0;
  list.forEach((item) => {
    total += item.total || 0;
    used += item.used || 0;
  });
  const percent = total ? (used / total) * 100 : 0;
  return { total, used, percent };
}

updateFooter("");
connectWS();
