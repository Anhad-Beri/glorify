const state = {
  mode: "full",
  runs: [],
  reports: [],
  lastFocus: null,
  scanTimers: []
};

const selectors = {
  navButtons: [...document.querySelectorAll(".nav-button")],
  views: [...document.querySelectorAll(".view")],
  modeButtons: [...document.querySelectorAll(".segmented-control button")],
  scanForm: document.querySelector("#scan-form"),
  settingsForm: document.querySelector("#settings-form"),
  computerModal: document.querySelector("#computer-modal"),
  runModal: document.querySelector("#run-modal"),
  toast: document.querySelector("#toast")
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", ...options.headers }
  });
  if (response.status === 401) {
    window.location.assign("/signin");
    throw new Error("Sign in required");
  }
  const result = await response.json();
  if (!response.ok) throw new Error(result.error ?? "Request failed");
  return result;
}

function showToast(message) {
  selectors.toast.textContent = message;
  selectors.toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { selectors.toast.hidden = true; }, 2600);
}

function openModal(modal, trigger) {
  state.lastFocus = trigger;
  modal.hidden = false;
  modal.classList.remove("is-closing");
  void modal.offsetWidth;
  modal.classList.add("is-opening");
  modal.querySelector(".modal-close").focus();
}

function closeModal(modal) {
  modal.classList.remove("is-opening");
  modal.classList.add("is-closing");
  window.setTimeout(() => {
    modal.hidden = true;
    modal.classList.remove("is-closing");
    state.lastFocus?.focus();
  }, window.matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 190);
}

selectors.navButtons.forEach((button) => {
  button.addEventListener("click", () => {
    selectors.navButtons.forEach((item) => {
      const active = item === button;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-pressed", String(active));
    });
    selectors.views.forEach((view) => {
      const active = view.dataset.panel === button.dataset.view;
      view.hidden = !active;
      view.classList.toggle("is-visible", active);
    });
  });
});

selectors.modeButtons.forEach((button) => {
  button.addEventListener("click", () => {
    state.mode = button.dataset.mode;
    const control = button.closest(".segmented-control");
    control.classList.toggle("is-fast", state.mode === "fast");
    control.classList.toggle("is-full", state.mode === "full");
    control.classList.remove("is-moving");
    void control.offsetWidth;
    control.classList.add("is-moving");
    window.setTimeout(() => control.classList.remove("is-moving"), 380);
    selectors.modeButtons.forEach((item) => {
      const active = item === button;
      item.classList.toggle("is-selected", active);
      item.setAttribute("aria-pressed", String(active));
    });
    document.querySelector("#mode-description").textContent = state.mode === "fast"
      ? "Fast · reuse the warmed ZAP session"
      : "Full scan · fresh spider and active scan";
  });
});

function severityClass(severity) {
  return `severity-${severity.toLowerCase()}`;
}

function reportButton(report) {
  const button = document.createElement("button");
  button.className = "outline-button";
  button.type = "button";
  button.textContent = "Open PDF";

  button.addEventListener("click", () => window.open(`/api/report?run=${encodeURIComponent(report.run)}`, "_blank"));
  return button;
}

function runDetailButton(run) {
  const button = document.createElement("button");
  button.className = "table-button";
  button.type = "button";
  button.textContent = "View run";
  button.addEventListener("click", () => {
    document.querySelector("#run-detail-id").textContent = run.id;
    document.querySelector("#run-detail-target").textContent = new URL(run.target).host;
    document.querySelector("#run-detail-status").textContent = run.status === "review" ? "Needs review" : "Complete";
    document.querySelector("#run-detail-mode").textContent = run.mode;
    document.querySelector("#run-detail-duration").textContent = run.duration;
    document.querySelector("#run-detail-when").textContent = run.when;
    document.querySelector("#run-detail-session").textContent = `Steel session ${run.session}`;

    const phases = document.querySelector("#run-detail-phases");
    phases.replaceChildren(...run.phases.map((phase, index) => {
      const item = document.createElement("li");
      item.textContent = phase;
      if (run.status === "review" && index >= 2) item.className = "is-incomplete";
      return item;
    }));

    const log = document.querySelector("#run-detail-log");
    log.replaceChildren(...run.log.map((entry) => {
      const line = document.createElement("span");
      line.textContent = entry;
      return line;
    }));
    openModal(selectors.runModal, button);
  });
  return button;
}

function renderReports(reports, runs) {

  const totalFindings = reports.reduce((sum, r) => sum + (r.total ?? 0), 0);
  const setStat = (id, value) => { const el = document.querySelector(id); if (el) el.textContent = value; };
  setStat("#ov-total", runs.length);
  setStat("#ov-completed", runs.filter((r) => r.status === "complete").length);
  setStat("#ov-findings", totalFindings);

  const library = document.querySelector("#report-library");
  library.replaceChildren();
  if (runs.length === 0) {
    const empty = document.createElement("p");
    empty.textContent = "No assessments yet. Run a scan to generate your first report.";
    library.append(empty);
    return;
  }
  for (const run of runs) {
    const report = reports.find((item) => item.run === run.id);
    const card = document.createElement("article");
    card.className = "report-card";
    const header = document.createElement("div");
    header.className = "report-card-header";
    const titleGroup = document.createElement("div");
    const title = document.createElement("h2");
    title.textContent = new URL(run.target).host;
    const copy = document.createElement("p");
    copy.className = "report-card-copy";
    copy.textContent = `${run.id} · ${run.mode}`;
    titleGroup.append(title, copy);
    const icon = document.createElement("span");
    icon.className = run.status === "review" ? "report-icon is-review" : "report-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = run.status === "review" ? "!" : "✓";
    header.append(titleGroup, icon);

    const result = document.createElement("div");
    result.className = "report-result";
    const resultLabel = document.createElement("span");
    resultLabel.textContent = "Result";
    const resultValue = document.createElement("strong");
    resultValue.className = run.status === "review" ? "status-review" : "status-complete";
    resultValue.textContent = run.result;
    result.append(resultLabel, resultValue);

    const footer = document.createElement("div");
    footer.className = "report-card-footer";
    const generated = document.createElement("span");
    generated.textContent = report ? `Generated ${report.generated.toLowerCase()}` : `Updated ${run.when.toLowerCase()}`;
    const actions = document.createElement("div");
    actions.className = "report-card-actions";
    actions.append(runDetailButton(run));
    if (report) {
      actions.append(reportButton(report));
    } else {
      const pending = document.createElement("button");
      pending.className = "outline-button";
      pending.type = "button";
      pending.disabled = true;
      pending.textContent = "Report pending";
      actions.append(pending);
    }
    footer.append(generated, actions);
    card.append(header, result, footer);
    library.append(card);
  }
}

function setProgress(activeIndex) {

  const items = [...document.querySelectorAll("#progress-list li")];
  items.forEach((item, index) => {
    item.classList.toggle("is-active", index === activeIndex);
    item.classList.toggle("is-complete", index < activeIndex);
    item.querySelector(".check").textContent = index < activeIndex ? "✓" : index === activeIndex ? "•" : "";
    const time = item.querySelector("time");
    if (time) time.textContent = index < activeIndex ? "done" : index === activeIndex ? "running" : "—";
  });
}

function addTerminalLine(text, className = "") {
  const line = document.createElement("span");
  line.textContent = text;
  if (className) line.className = className;
  document.querySelector("#agent-trace").append(line);
  const modalLine = line.cloneNode(true);
  if (text.startsWith("$")) modalLine.className = "terminal-command";
  document.querySelector("#computer-terminal").append(modalLine);
}

const PHASE_INDEX = { crawling: 0, scanning: 2, reporting: 3 };

function renderLiveFindings(findings, reportReady, runId) {
  findings = findings ?? [];
  const sev = (prefix) => findings.filter((f) => String(f.severity ?? "").toLowerCase().startsWith(prefix)).length;
  const metrics = [
    ["Total", findings.length, ""],
    ["High", sev("high"), "metric-high"],
    ["Medium", sev("med"), "metric-medium"],
    ["Low", sev("low"), "metric-low"],
    ["Info", sev("info"), ""]
  ];
  const metricRow = document.querySelector(".findings-panel .metric-row");
  if (metricRow) {
    metricRow.replaceChildren(...metrics.map(([label, value, cls]) => {
      const cell = document.createElement("div");
      if (cls) cell.className = cls;
      const strong = document.createElement("strong");
      strong.textContent = value;
      const span = document.createElement("span");
      span.textContent = label;
      cell.append(strong, span);
      return cell;
    }));
  }
  const tbody = document.querySelector(".findings-panel tbody");
  if (tbody) {
    tbody.replaceChildren();
    if (findings.length === 0) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 4;
      cell.textContent = "No findings recorded for this run.";
      row.append(cell);
      tbody.append(row);
    } else {
      findings.slice(0, 60).forEach((finding) => {
        const row = document.createElement("tr");
        const severity = document.createElement("td");
        severity.className = severityClass(String(finding.severity ?? "info"));
        severity.textContent = finding.severity ?? "Info";
        const category = document.createElement("td");
        category.textContent = finding.category ?? finding.tool ?? "Finding";
        const evidence = document.createElement("td");
        evidence.textContent = finding.tool ?? "—";
        const endpoint = document.createElement("td");
        const code = document.createElement("code");
        code.textContent = finding.endpoint ?? "—";
        endpoint.append(code);
        row.append(severity, category, evidence, endpoint);
        tbody.append(row);
      });
    }
  }
  const trigger = document.querySelector(".findings-panel .report-trigger");
  if (trigger) {
    trigger.disabled = !reportReady;
    const href = runId ? `/api/report?run=${encodeURIComponent(runId)}` : "/api/report";
    trigger.onclick = () => reportReady ? window.open(href, "_blank") : showToast("Report is not ready yet");
  }
}

function pollRealStatus(submitButton) {
  window.clearInterval(state.poller);
  let lastLines = 0;
  state.poller = window.setInterval(async () => {
    let status;
    try { status = await api("/api/status"); } catch { return; }

    const lines = String(status.log ?? "").split("\n").filter(Boolean);
    for (let i = lastLines; i < lines.length; i += 1) addTerminalLine(lines[i]);
    lastLines = lines.length;

    if (status.phase && PHASE_INDEX[status.phase] !== undefined) setProgress(PHASE_INDEX[status.phase]);
    if (status.progress && status.progress.ascan != null) {
      document.querySelector("#progress-time").textContent = `Active scan ${status.progress.ascan}% · ${status.progress.alerts ?? 0} alerts`;
    }

    if (status.status === "done") {
      window.clearInterval(state.poller);
      setProgress(4);
      addTerminalLine("Run complete — report ready", "success-text");
      document.querySelector("#trace-status").textContent = "Complete";
      document.querySelector("#progress-time").textContent = `Complete · ${(status.findings ?? []).length} findings`;
      submitButton.disabled = false;
      renderLiveFindings(status.findings, status.report_ready, status.run_id);
      showToast(`Scan complete · ${(status.findings ?? []).length} findings`);

      refreshReports();
    } else if (status.status === "error") {
      window.clearInterval(state.poller);
      addTerminalLine(`Error: ${status.error ?? "scan failed"}`, "warning-text");
      document.querySelector("#trace-status").textContent = "Error";
      document.querySelector("#progress-time").textContent = "Failed";
      submitButton.disabled = false;
      showToast(status.error ?? "Scan failed");
    }
  }, 1500);
}

selectors.scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = document.querySelector("#target-url").value;
  const submitButton = selectors.scanForm.querySelector("button[type='submit']");
  submitButton.disabled = true;

  try {
    const run = await api("/api/runs", { method: "POST", body: JSON.stringify({ target, mode: state.mode }) });
    renderLiveFindings([], false);
    document.querySelector("#trace-status").textContent = "Running";
    document.querySelector("#progress-time").textContent = "In progress";
    document.querySelector("#agent-trace").replaceChildren();
    document.querySelector("#computer-terminal").replaceChildren();
    addTerminalLine("STEEL COMPUTER / LIVE SESSION", "success-text");
    addTerminalLine(`$ launching ${state.mode} pentest against ${run.target}`);
    setProgress(0);
    openModal(selectors.computerModal, submitButton);
    pollRealStatus(submitButton);
  } catch (error) {
    submitButton.disabled = false;
    showToast(error.message);
  }
});

document.querySelectorAll(".modal").forEach((modal) => {
  modal.querySelector(".modal-close").addEventListener("click", () => closeModal(modal.parentElement));
});

document.querySelectorAll(".modal-backdrop").forEach((backdrop) => {
  backdrop.addEventListener("click", (event) => { if (event.target === backdrop) closeModal(backdrop); });
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  const openModalElement = [...document.querySelectorAll(".modal-backdrop")].find((modal) => !modal.hidden);
  if (openModalElement) closeModal(openModalElement);
});

selectors.settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(selectors.settingsForm);
  const status = document.querySelector("#settings-status");
  const button = selectors.settingsForm.querySelector("button[type='submit']");
  button.disabled = true;
  status.textContent = "Saving…";
  try {
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({ defaultMode: form.get("defaultMode") })
    });
    status.textContent = "Saved";
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#signout-button").addEventListener("click", async () => {
  await api("/api/signout", { method: "POST" });
  window.location.assign("/signin");
});

function initializeAmbientBackgrounds() {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const canvases = [...document.querySelectorAll(".ambient-background")].map((canvas) => ({
    canvas,
    context: canvas.getContext("2d"),
    width: 0,
    height: 0,
    dpr: 1,
    particles: [],
    nodes: [],
    columns: 15,
    rows: 7,
    lastFrame: 0
  }));

  function resize(entry) {
    const bounds = entry.canvas.getBoundingClientRect();
    const nextWidth = Math.max(1, Math.round(bounds.width));
    const nextHeight = Math.max(1, Math.round(bounds.height));
    const nextDpr = Math.min(window.devicePixelRatio || 1, 2);
    if (entry.width === nextWidth && entry.height === nextHeight && entry.dpr === nextDpr) return;
    entry.width = nextWidth;
    entry.height = nextHeight;
    entry.dpr = nextDpr;
    entry.canvas.width = Math.round(nextWidth * nextDpr);
    entry.canvas.height = Math.round(nextHeight * nextDpr);
    entry.context.setTransform(nextDpr, 0, 0, nextDpr, 0, 0);
    if (entry.canvas.dataset.animation === "orbital") {
      const count = Math.max(34, Math.round(nextWidth / 15));
      entry.particles = Array.from({ length: count }, (_, index) => ({
        angle: index * 2.399,
        radius: 28 + (index % 15) * Math.min(nextWidth, nextHeight) * 0.022,
        speed: 0.00024 + (index % 7) * 0.000029,
        drift: index * 0.71,
        size: 1.1 + (index % 4) * 0.45
      }));
    }
    if (entry.canvas.dataset.animation === "lattice") {
      entry.columns = nextWidth < 520 ? 9 : 15;
      entry.rows = nextWidth < 520 ? 9 : 7;
      entry.nodes = [];
      for (let row = 0; row < entry.rows; row += 1) {
        for (let column = 0; column < entry.columns; column += 1) {
          const x = nextWidth * 0.08 + column * nextWidth * 0.84 / (entry.columns - 1);
          const y = nextHeight * 0.12 + row * nextHeight * 0.76 / (entry.rows - 1);
          entry.nodes.push({ x, y, originX: x, originY: y, velocityX: 0, velocityY: 0, column, row });
        }
      }
      entry.lastFrame = 0;
    }
  }

  function palette() {
    const styles = getComputedStyle(document.documentElement);
    return {
      background: styles.getPropertyValue("--bg").trim(),
      panel: styles.getPropertyValue("--panel").trim(),
      line: styles.getPropertyValue("--line").trim(),
      accent: styles.getPropertyValue("--accent").trim(),
      soft: "#62e8c8"
    };
  }

  function clear(entry, colors) {
    entry.context.fillStyle = colors.background;
    entry.context.fillRect(0, 0, entry.width, entry.height);
  }

  function drawLattice(entry, time, colors, still) {
    const { context: ctx, width, height, columns, rows, nodes } = entry;
    const delta = Math.min(2, (time - entry.lastFrame || 16) / 16);
    const flowTime = still ? 1800 : time * 0.09;
    entry.lastFrame = time;
    const pulse = still ? columns * 0.46 : ((flowTime * 0.0018) % 1) * (columns + 5) - 2;

    nodes.forEach((node) => {
      const distance = node.column - pulse;
      const force = Math.exp(-distance * distance * 0.34) * Math.sin(flowTime * 0.006 - node.row * 0.55) * height * 0.035;
      const targetY = node.originY + force + Math.sin(flowTime * 0.0008 + node.column * 0.42 + node.row * 0.31) * (still ? 0 : 3);
      node.velocityY += (targetY - node.y) * 0.055 * delta;
      node.velocityX += (node.originX - node.x) * 0.045 * delta;
      node.velocityX *= 0.88;
      node.velocityY *= 0.88;
      node.x += node.velocityX * delta;
      node.y += node.velocityY * delta;
    });

    ctx.lineWidth = 1;
    nodes.forEach((node) => {
      [[1, 0], [0, 1]].forEach(([columnStep, rowStep]) => {
        const nextColumn = node.column + columnStep;
        const nextRow = node.row + rowStep;
        if (nextColumn >= columns || nextRow >= rows) return;
        const other = nodes[nextRow * columns + nextColumn];
        const hot = Math.max(0, 1 - Math.abs((node.column + other.column) * 0.5 - pulse) / 2.6);
        ctx.strokeStyle = hot > 0.2 ? colors.accent : colors.line;
        ctx.globalAlpha = 0.16 + hot * 0.58;
        ctx.beginPath();
        ctx.moveTo(node.x, node.y);
        ctx.lineTo(other.x, other.y);
        ctx.stroke();
      });
    });
    nodes.forEach((node) => {
      const hot = Math.max(0, 1 - Math.abs(node.column - pulse) / 2.2);
      ctx.globalAlpha = 0.42 + hot * 0.58;
      ctx.fillStyle = hot > 0.12 ? colors.soft : colors.line;
      ctx.shadowColor = colors.accent;
      ctx.shadowBlur = hot * 16;
      ctx.beginPath();
      ctx.arc(node.x, node.y, 1.7 + hot * 1.9, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    });
    ctx.globalAlpha = 1;
  }

  function drawOrbital(entry, time, colors, still) {
    const { context: ctx, width, height, particles } = entry;
    const t = still ? 1400 : time * 0.133;
    const centerX = width * 0.5 + Math.sin(t * 0.00023) * width * 0.01;
    const centerY = height * 0.5 + Math.sin(t * 0.00031 + 1.2) * height * 0.008;
    ctx.lineWidth = 1;
    ctx.strokeStyle = colors.panel;
    ctx.globalAlpha = 0.55;
    for (let radius = 46; radius < Math.min(width, height) * 0.62; radius += 42) {
      ctx.beginPath();
      ctx.ellipse(centerX, centerY, radius * 1.55, radius, -0.18, 0, Math.PI * 2);
      ctx.stroke();
    }
    ctx.globalCompositeOperation = "lighter";
    particles.forEach((particle, index) => {
      if (!still) particle.angle += particle.speed * 16;
      const wobble = Math.sin(t * 0.0012 + particle.drift) * 10;
      const x = centerX + Math.cos(particle.angle) * (particle.radius * 1.55 + wobble);
      const y = centerY + Math.sin(particle.angle) * (particle.radius + wobble * 0.35);
      if (index % 6 === 0) {
        const linked = particles[(index + 7) % particles.length];
        ctx.strokeStyle = colors.accent;
        ctx.globalAlpha = 0.08;
        ctx.beginPath();
        ctx.moveTo(x, y);
        ctx.lineTo(centerX + Math.cos(linked.angle) * linked.radius * 1.55, centerY + Math.sin(linked.angle) * linked.radius);
        ctx.stroke();
      }
      ctx.fillStyle = index % 5 ? colors.accent : colors.soft;
      ctx.globalAlpha = 0.48 + (index % 4) * 0.12;
      ctx.beginPath();
      ctx.arc(x, y, particle.size, 0, Math.PI * 2);
      ctx.fill();
    });
    ctx.globalCompositeOperation = "source-over";
    ctx.globalAlpha = 1;
    ctx.shadowColor = colors.accent;
    ctx.shadowBlur = 22;
    ctx.fillStyle = colors.accent;
    ctx.beginPath();
    ctx.arc(centerX, centerY, 4.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
  }

  function drawGyroscope(entry, time, colors, still) {
    const { context: ctx, width, height } = entry;
    const t = still ? 2200 : time * 0.42;
    const compact = width < 520;
    const verticalShift = height * 0.061;
    const hubs = compact
      ? [{ x: width * 0.5, y: height * 0.28 + verticalShift, radius: 30, speed: 0.00045 }, { x: width * 0.28, y: height * 0.76 + verticalShift, radius: 38, speed: -0.00032 }, { x: width * 0.74, y: height * 0.78 + verticalShift, radius: 26, speed: 0.0006 }]
      : [{ x: width * 0.2, y: height * 0.61 + verticalShift, radius: 45, speed: 0.00045 }, { x: width * 0.51, y: height * 0.42 + verticalShift, radius: 58, speed: -0.00032 }, { x: width * 0.81, y: height * 0.66 + verticalShift, radius: 38, speed: 0.0006 }];
    const bezier = (start, controlA, controlB, end, amount) => {
      const inverse = 1 - amount;
      return inverse ** 3 * start + 3 * inverse ** 2 * amount * controlA + 3 * inverse * amount ** 2 * controlB + amount ** 3 * end;
    };

    [[hubs[0], hubs[1]], [hubs[1], hubs[2]], [hubs[2], hubs[0]]].forEach(([start, end], routeIndex) => {
      const bend = (routeIndex - 1) * height * 0.17;
      const controlA = { x: start.x + (end.x - start.x) * 0.35, y: start.y + bend };
      const controlB = { x: start.x + (end.x - start.x) * 0.7, y: end.y - bend };
      ctx.strokeStyle = colors.line;
      ctx.globalAlpha = 0.36;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(start.x, start.y);
      ctx.bezierCurveTo(controlA.x, controlA.y, controlB.x, controlB.y, end.x, end.y);
      ctx.stroke();
      for (let bead = 0; bead < 4; bead += 1) {
        const position = (t * 0.00012 + bead * 0.25 + routeIndex * 0.17) % 1;
        const x = bezier(start.x, controlA.x, controlB.x, end.x, position);
        const y = bezier(start.y, controlA.y, controlB.y, end.y, position);
        ctx.fillStyle = bead === 0 ? colors.soft : colors.accent;
        ctx.globalAlpha = 0.45 + bead * 0.13;
        ctx.shadowColor = colors.accent;
        ctx.shadowBlur = bead === 0 ? 16 : 7;
        ctx.beginPath();
        ctx.arc(x, y, bead === 0 ? 3.2 : 2, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    });

    hubs.forEach((hub, index) => {
      const phase = t * hub.speed + index * 1.7;
      ctx.save();
      ctx.translate(hub.x, hub.y);
      ctx.rotate(phase);
      ctx.strokeStyle = colors.line;
      ctx.globalAlpha = 0.65;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.ellipse(0, 0, hub.radius * 1.45, hub.radius * 0.56, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.rotate(-phase * 1.7);
      ctx.strokeStyle = colors.accent;
      ctx.globalAlpha = 0.42;
      ctx.beginPath();
      ctx.ellipse(0, 0, hub.radius, hub.radius * 0.38, 0.82, 0, Math.PI * 2);
      ctx.stroke();
      ctx.rotate(phase * 2.3);
      ctx.beginPath();
      ctx.arc(0, 0, hub.radius * 0.7, 0, Math.PI * 1.45);
      ctx.stroke();
      ctx.shadowColor = colors.accent;
      ctx.shadowBlur = 18;
      ctx.fillStyle = colors.accent;
      ctx.globalAlpha = 0.92;
      ctx.beginPath();
      ctx.arc(Math.cos(phase) * hub.radius * 0.7, Math.sin(phase) * hub.radius * 0.7, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
      ctx.shadowBlur = 0;
      ctx.fillStyle = colors.panel;
      ctx.globalAlpha = 1;
      ctx.beginPath();
      ctx.arc(hub.x, hub.y, 7, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = colors.accent;
      ctx.stroke();
    });
    ctx.globalAlpha = 1;
  }

  const renderers = { lattice: drawLattice, orbital: drawOrbital, gyroscope: drawGyroscope };
  function draw(time) {
    const colors = palette();
    canvases.forEach((entry) => {
      if (entry.canvas.closest(".view").hidden) return;
      resize(entry);
      clear(entry, colors);
      const animationScale = entry.canvas.dataset.animation === "gyroscope"
        ? 1.44375
        : entry.canvas.dataset.animation === "orbital" ? 1.953125 : 1.25;
      entry.context.save();
      entry.context.translate(entry.width * 0.5, entry.height * 0.5);
      entry.context.scale(animationScale, animationScale);
      entry.context.translate(entry.width * -0.5, entry.height * -0.5);
      renderers[entry.canvas.dataset.animation]?.(entry, time, colors, reducedMotion.matches);
      entry.context.restore();
    });
    if (!reducedMotion.matches) window.requestAnimationFrame(draw);
  }

  const viewObserver = new MutationObserver(() => {
    if (reducedMotion.matches) window.requestAnimationFrame(draw);
  });
  canvases.forEach((entry) => viewObserver.observe(entry.canvas.closest(".view"), { attributes: true, attributeFilter: ["hidden"] }));
  reducedMotion.addEventListener("change", () => window.requestAnimationFrame(draw));
  window.requestAnimationFrame(draw);
}

function setComputerStatus(online) {
  const el = document.querySelector(".computer-status");
  if (!el || !el.lastChild) return;
  el.lastChild.textContent = online ? "Steel Computer online" : "Steel Computer offline";
  el.classList.toggle("is-offline", !online);
}

function resetScanView() {
  const trace = document.querySelector("#agent-trace");
  if (trace) {
    trace.replaceChildren();
    const line = document.createElement("span");
    line.textContent = "Awaiting scan — enter a target and press Run.";
    trace.append(line);
  }
  const ts = document.querySelector("#trace-status");
  if (ts) ts.textContent = "Idle";
  const pt = document.querySelector("#progress-time");
  if (pt) pt.textContent = "Not started";
  document.querySelectorAll("#progress-list li").forEach((li) => {
    li.classList.remove("is-active", "is-complete");
    const check = li.querySelector(".check"); if (check) check.textContent = "";
    const time = li.querySelector("time"); if (time) time.textContent = "—";
  });
  renderLiveFindings([], false);
}

async function refreshReports() {
  try {
    const dashboard = await api("/api/dashboard");
    state.runs = dashboard.runs;
    state.reports = dashboard.reports;
    renderReports(dashboard.reports, dashboard.runs);
  } catch {  }
}

async function initialize() {
  resetScanView();
  try {
    const dashboard = await api("/api/dashboard");
    state.runs = dashboard.runs;
    state.reports = dashboard.reports;
    document.querySelector("#account-email").textContent = dashboard.user.email;
    renderReports(dashboard.reports, dashboard.runs);

    try { const h = await api("/api/health"); setComputerStatus(!!h.computer); } catch { setComputerStatus(false); }

    const dm = dashboard.settings.defaultMode === "fast" ? "fast" : "full";
    selectors.settingsForm.elements.defaultMode.value = dm;
    if (dm !== state.mode) {
      const btn = selectors.modeButtons.find((b) => b.dataset.mode === dm);
      if (btn) btn.click();
    }
  } catch (error) {
    setComputerStatus(false);
    showToast(error.message);
  }
}

initializeAmbientBackgrounds();
initialize();
