const grid = document.getElementById("grid");
const empty = document.getElementById("empty");
const wsStatus = document.getElementById("ws-status");
const nodeCount = document.getElementById("node-count");
const lastUpdated = document.getElementById("last-updated");
const loginModal = document.getElementById("login-modal");
const loginForm = document.getElementById("login-form");
const loginError = document.getElementById("login-error");

const state = {
  token: localStorage.getItem("cm_token") || "",
  ws: null,
  nodes: new Map(),
  reconnectTimer: null,
};

function setWsStatus(text, online) {
  wsStatus.querySelector(".label").textContent = text;
  wsStatus.style.background = online
    ? "rgba(31, 93, 255, 0.12)"
    : "rgba(239, 68, 68, 0.12)";
  wsStatus.style.borderColor = online
    ? "rgba(31, 93, 255, 0.2)"
    : "rgba(239, 68, 68, 0.3)";
  wsStatus.style.color = online ? "#1f3bd3" : "#dc2626";
  wsStatus.querySelector(".dot").style.background = online ? "#1f5dff" : "#ef4444";
}

function showLogin() {
  loginModal.classList.remove("hidden");
}

function hideLogin() {
  loginModal.classList.add("hidden");
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
  state.token = data.token;
  localStorage.setItem("cm_token", data.token);
  hideLogin();
  connectWS();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(loginForm);
  const username = formData.get("username");
  const password = formData.get("password");
  try {
    await login(username, password);
  } catch (error) {
    loginError.textContent = error.message;
  }
});

function connectWS() {
  if (!state.token) {
    showLogin();
    return;
  }
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${protocol}://${location.host}/ws?token=${encodeURIComponent(
    state.token
  )}`;
  const ws = new WebSocket(wsUrl);
  state.ws = ws;

  setWsStatus("连接中...", false);

  ws.onopen = () => {
    setWsStatus("已连接", true);
  };

  ws.onclose = () => {
    setWsStatus("已断开", false);
    scheduleReconnect();
  };

  ws.onerror = () => {
    setWsStatus("连接异常", false);
    ws.close();
  };

  ws.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type === "snapshot") {
        updateNodes(payload.nodes || []);
        lastUpdated.textContent = new Date(
          (payload.generated_at || 0) * 1000
        ).toLocaleTimeString();
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

function updateNodes(nodes) {
  nodeCount.textContent = nodes.length;
  empty.style.display = nodes.length ? "none" : "block";

  const activeIds = new Set();
  nodes.forEach((node, index) => {
    const id = node?.stats?.node_id || `node-${index}`;
    activeIds.add(id);
    let card = state.nodes.get(id);
    if (!card) {
      card = createCard();
      card.style.animationDelay = `${index * 0.05}s`;
      grid.appendChild(card);
      state.nodes.set(id, card);
    }
    updateCard(card, node);
  });

  for (const [id, card] of state.nodes.entries()) {
    if (!activeIds.has(id)) {
      card.remove();
      state.nodes.delete(id);
    }
  }
}

function createCard() {
  const card = document.createElement("article");
  card.className = "card";
  card.innerHTML = `
    <div class="card-head">
      <div>
        <div class="node-name" data-field="name"></div>
        <div class="node-meta" data-field="meta"></div>
      </div>
      <div class="status" data-field="status">
        <span class="dot"></span>
        <span class="status-text"></span>
      </div>
    </div>
    <div class="metric">
      <div class="metric-head">
        <span>CPU</span>
        <span data-field="cpu-value">--</span>
      </div>
      <div class="meter"><span class="fill" data-field="cpu-bar"></span></div>
      <div class="metric-sub" data-field="cpu-load">Load --</div>
    </div>
    <div class="metric">
      <div class="metric-head">
        <span>内存</span>
        <span data-field="mem-value">--</span>
      </div>
      <div class="meter"><span class="fill mem" data-field="mem-bar"></span></div>
      <div class="metric-sub" data-field="mem-detail">--</div>
    </div>
    <div class="metric">
      <div class="metric-head">
        <span>磁盘</span>
        <span data-field="disk-value">--</span>
      </div>
      <div class="meter"><span class="fill disk" data-field="disk-bar"></span></div>
      <div class="metric-sub" data-field="disk-detail">--</div>
      <div class="metric-sub" data-field="disk-partitions">--</div>
    </div>
    <div class="metric">
      <div class="metric-head">
        <span>网络</span>
        <span data-field="net-total">--</span>
      </div>
      <div class="io-grid">
        <div data-field="net-up">--</div>
        <div data-field="net-down">--</div>
        <div data-field="disk-read">--</div>
        <div data-field="disk-write">--</div>
      </div>
    </div>
    <div class="metric">
      <div class="metric-head">
        <span>连通性测试</span>
        <span data-field="test-summary">--</span>
      </div>
      <div class="test-list" data-field="test-list"></div>
    </div>
    <div class="footer">
      <div data-field="uptime">--</div>
      <div data-field="last-seen">--</div>
    </div>
  `;

  const fields = {
    name: card.querySelector('[data-field="name"]'),
    meta: card.querySelector('[data-field="meta"]'),
    status: card.querySelector('[data-field="status"]'),
    statusText: card.querySelector('.status-text'),
    cpuValue: card.querySelector('[data-field="cpu-value"]'),
    cpuBar: card.querySelector('[data-field="cpu-bar"]'),
    cpuLoad: card.querySelector('[data-field="cpu-load"]'),
    memValue: card.querySelector('[data-field="mem-value"]'),
    memBar: card.querySelector('[data-field="mem-bar"]'),
    memDetail: card.querySelector('[data-field="mem-detail"]'),
    diskValue: card.querySelector('[data-field="disk-value"]'),
    diskBar: card.querySelector('[data-field="disk-bar"]'),
    diskDetail: card.querySelector('[data-field="disk-detail"]'),
    diskPartitions: card.querySelector('[data-field="disk-partitions"]'),
    netTotal: card.querySelector('[data-field="net-total"]'),
    netUp: card.querySelector('[data-field="net-up"]'),
    netDown: card.querySelector('[data-field="net-down"]'),
    diskRead: card.querySelector('[data-field="disk-read"]'),
    diskWrite: card.querySelector('[data-field="disk-write"]'),
    testSummary: card.querySelector('[data-field="test-summary"]'),
    testList: card.querySelector('[data-field="test-list"]'),
    uptime: card.querySelector('[data-field="uptime"]'),
    lastSeen: card.querySelector('[data-field="last-seen"]'),
  };
  card._fields = fields;
  return card;
}

function updateCard(card, node) {
  const fields = card._fields;
  const stats = node.stats || {};
  const cpu = stats.cpu || {};
  const mem = stats.memory || {};
  const diskList = stats.disk || [];
  const diskIO = stats.disk_io || {};
  const net = stats.network || {};
  const tests = stats.network_tests || [];

  const nodeName = stats.node_name || stats.node_id || "未知节点";
  fields.name.textContent = nodeName;
  fields.meta.textContent = `${stats.hostname || "--"} · ${stats.os || "--"} · ${
    stats.arch || "--"
  }`;

  const status = node.status === "offline" ? "离线" : "在线";
  fields.status.classList.toggle("offline", node.status === "offline");
  fields.statusText.textContent = status;

  const cpuPercent = clamp(cpu.usage_percent || 0);
  fields.cpuValue.textContent = `${cpuPercent.toFixed(1)}%`;
  fields.cpuBar.style.width = `${cpuPercent}%`;
  fields.cpuLoad.textContent = `Load ${formatLoad(cpu)}`;

  const memPercent = clamp(mem.used_percent || 0);
  fields.memValue.textContent = `${memPercent.toFixed(1)}%`;
  fields.memBar.style.width = `${memPercent}%`;
  fields.memDetail.textContent = `${formatBytes(mem.used)} / ${formatBytes(
    mem.total
  )}`;

  const diskAgg = aggregateDisk(diskList);
  const diskPercent = clamp(diskAgg.percent);
  fields.diskValue.textContent = `${diskPercent.toFixed(1)}%`;
  fields.diskBar.style.width = `${diskPercent}%`;
  fields.diskDetail.textContent = `${formatBytes(diskAgg.used)} / ${formatBytes(
    diskAgg.total
  )}`;
  fields.diskPartitions.textContent = formatPartitions(diskList);

  fields.netTotal.textContent = `累计 ${formatBytes(net.bytes_sent)} / ${formatBytes(
    net.bytes_recv
  )}`;
  fields.netUp.textContent = `↑ ${formatRate(net.tx_bytes_per_sec)}`;
  fields.netDown.textContent = `↓ ${formatRate(net.rx_bytes_per_sec)}`;
  fields.diskRead.textContent = `读 ${formatRate(diskIO.read_bytes_per_sec)}`;
  fields.diskWrite.textContent = `写 ${formatRate(diskIO.write_bytes_per_sec)}`;

  updateNetworkTests(fields, tests);

  fields.uptime.textContent = `运行 ${formatUptime(stats.uptime_sec || 0)}`;
  fields.lastSeen.textContent = `更新 ${formatTime(node.last_seen || 0)}`;
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

function formatPartitions(list) {
  if (!list.length) return "分区 --";
  const sorted = [...list].sort(
    (a, b) => (b.used_percent || 0) - (a.used_percent || 0)
  );
  return sorted
    .slice(0, 2)
    .map((item) => {
      const label = item.mountpoint || item.device || "--";
      return `${label} ${formatBytes(item.used)} / ${formatBytes(item.total)}`;
    })
    .join(" · ");
}

function updateNetworkTests(fields, tests) {
  if (!tests.length) {
    fields.testSummary.textContent = "--";
    fields.testList.textContent = "未配置网络测试";
    return;
  }

  const okCount = tests.filter((test) => test.status === "ok").length;
  fields.testSummary.textContent = `${okCount}/${tests.length} OK`;

  fields.testList.innerHTML = "";
  tests.forEach((test) => {
    const item = document.createElement("div");
    item.className = "test-item";
    const badge = document.createElement("div");
    badge.className = `test-badge ${test.status || "error"}`;
    const dot = document.createElement("span");
    dot.className = "test-dot";
    badge.appendChild(dot);
    const statusText = document.createElement("span");
    statusText.textContent = formatStatus(test.status);
    badge.appendChild(statusText);

    const meta = document.createElement("div");
    meta.className = "test-meta";
    const label = document.createElement("span");
    label.textContent = formatTestLabel(test);
    meta.appendChild(label);

    const value = document.createElement("span");
    value.textContent = formatTestValue(test);

    item.appendChild(badge);
    item.appendChild(meta);
    item.appendChild(value);

    if (test.error) {
      item.title = test.error;
    }

    fields.testList.appendChild(item);
  });
}

function formatStatus(status) {
  if (status === "ok") return "可达";
  if (status === "timeout") return "超时";
  return "异常";
}

function formatTestLabel(test) {
  const type = (test.type || "icmp").toUpperCase();
  const host = test.host || "--";
  const port = test.port ? `:${test.port}` : "";
  const name = test.name && test.name !== host ? `${test.name} · ` : "";
  return `${name}${type} ${host}${port}`;
}

function formatTestValue(test) {
  if (test.latency_ms !== null && test.latency_ms !== undefined) {
    return `${test.latency_ms.toFixed(1)} ms`;
  }
  if (test.packet_loss !== undefined) {
    return `${test.packet_loss.toFixed(0)}% loss`;
  }
  return "--";
}

if (!state.token) {
  showLogin();
}

connectWS();
