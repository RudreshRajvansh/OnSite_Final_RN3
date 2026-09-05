const SVG = "http://www.w3.org/2000/svg";

const state = {
  spec: null,
  runs: [],
  current: null,
  result: null,
  slack: 0,
  playhead: -1,
  timer: null,
};

function el(tag, attrs, text) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

function html(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path} -> ${response.status}`);
  return response.json();
}

function rankNet(spec) {
  const BIG = 1e9;
  const rank = {};
  for (const place of spec.places) {
    rank["p:" + place.id] = place.tokens && place.tokens.length ? 0 : BIG;
  }
  for (let pass = 0; pass < spec.transitions.length + 2; pass++) {
    for (const t of spec.transitions) {
      const inputs = t.consumes.map((p) => rank["p:" + p] ?? BIG);
      const value = inputs.length ? Math.max(...inputs) + 1 : 0;
      if (value < (rank["t:" + t.id] ?? BIG)) rank["t:" + t.id] = value;
    }
    for (const t of spec.transitions) {
      const source = rank["t:" + t.id] ?? BIG;
      if (source >= BIG) continue;
      for (const p of t.produces) {
        if (source + 1 < (rank["p:" + p] ?? BIG)) rank["p:" + p] = source + 1;
      }
    }
  }
  return rank;
}

function layoutNet(spec) {
  const rank = rankNet(spec);
  const columns = new Map();
  const nodes = new Map();
  const push = (key, node) => {
    const level = rank[key] ?? 0;
    if (!columns.has(level)) columns.set(level, []);
    columns.get(level).push(key);
    nodes.set(key, node);
  };
  for (const place of spec.places) {
    push("p:" + place.id, { kind: "place", id: place.id, data: place });
  }
  for (const t of spec.transitions) {
    push("t:" + t.id, { kind: "transition", id: t.id, data: t });
  }

  const levels = [...columns.keys()].sort((a, b) => a - b);
  const colWidth = 132;
  const rowHeight = 74;
  let maxRows = 1;
  levels.forEach((level, index) => {
    const keys = columns.get(level);
    maxRows = Math.max(maxRows, keys.length);
    keys.forEach((key, row) => {
      const node = nodes.get(key);
      node.x = 70 + index * colWidth;
      node.y = 46 + row * rowHeight;
    });
  });
  return {
    nodes,
    width: 70 + levels.length * colWidth + 60,
    height: 46 + maxRows * rowHeight + 20,
  };
}

function markingAt(spec, witness, upto) {
  const marking = {};
  for (const place of spec.places) marking[place.id] = (place.tokens || []).length;
  for (let i = 0; i <= upto && witness && i < witness.length; i++) {
    const t = spec.transitions.find((x) => x.id === witness[i].transition);
    if (!t) continue;
    for (const p of t.consumes) marking[p] = Math.max(0, (marking[p] || 0) - 1);
    for (const p of t.produces) marking[p] = (marking[p] || 0) + 1;
  }
  return marking;
}

function renderNet() {
  const svg = document.getElementById("net");
  svg.textContent = "";
  if (!state.spec) return;
  const spec = state.spec.spec;
  const { nodes, width, height } = layoutNet(spec);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("height", height);

  const defs = el("defs");
  const marker = el("marker", {
    id: "arrow",
    viewBox: "0 0 10 10",
    refX: "9",
    refY: "5",
    markerWidth: "7",
    markerHeight: "7",
    orient: "auto-start-reverse",
  });
  marker.appendChild(el("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "#2c3546" }));
  defs.appendChild(marker);
  svg.appendChild(defs);

  const witness = state.result && state.result.outcome.witness;
  const fired = new Set();
  let active = null;
  if (witness) {
    for (let i = 0; i <= state.playhead && i < witness.length; i++) {
      fired.add(witness[i].transition);
      active = witness[i];
    }
  }
  const hot = new Set();
  if (active) {
    const t = spec.transitions.find((x) => x.id === active.transition);
    if (t) {
      t.consumes.forEach((p) => hot.add(p + "->" + t.id));
      t.produces.forEach((p) => hot.add(t.id + "->" + p));
    }
  }

  for (const t of spec.transitions) {
    const from = nodes.get("t:" + t.id);
    for (const p of t.consumes) {
      const place = nodes.get("p:" + p);
      if (place) svg.appendChild(arc(place, from, hot.has(p + "->" + t.id)));
    }
    for (const p of t.produces) {
      const place = nodes.get("p:" + p);
      if (place) svg.appendChild(arc(from, place, hot.has(t.id + "->" + p)));
    }
  }

  const marking = markingAt(spec, witness, state.playhead);
  for (const node of nodes.values()) {
    if (node.kind === "place") {
      const count = marking[node.id] || 0;
      const classes = ["place"];
      if (count > 0) classes.push("marked");
      if ((spec.final || []).includes(node.id)) classes.push("final");
      svg.appendChild(
        el("circle", { cx: node.x, cy: node.y, r: 19, class: classes.join(" ") })
      );
      for (let i = 0; i < Math.min(count, 3); i++) {
        svg.appendChild(
          el("circle", {
            cx: node.x - 6 + i * 6,
            cy: node.y,
            r: 2.6,
            class: "token",
          })
        );
      }
      svg.appendChild(
        el("text", {
          x: node.x,
          y: node.y + 33,
          class: "label sub",
          "text-anchor": "middle",
        }, node.id)
      );
    } else {
      const classes = ["transition"];
      if (fired.has(node.id)) classes.push("fired");
      if (active && active.transition === node.id) {
        classes.push("active");
        if (!active.observed) classes.push("unobserved");
      }
      svg.appendChild(
        el("rect", {
          x: node.x - 58,
          y: node.y - 15,
          width: 116,
          height: 30,
          class: classes.join(" "),
        })
      );
      svg.appendChild(
        el("text", {
          x: node.x,
          y: node.y + 1,
          class: "label",
          "text-anchor": "middle",
        }, node.id.length > 17 ? node.id.slice(0, 16) + "…" : node.id)
      );
      svg.appendChild(
        el("text", {
          x: node.x,
          y: node.y + 12,
          class: "label sub",
          "text-anchor": "middle",
        }, node.data.principal)
      );
    }
  }
}

function arc(from, to, isHot) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy) || 1;
  const padFrom = from.kind === "place" ? 21 : 62;
  const padTo = to.kind === "place" ? 23 : 62;
  const x1 = from.x + (dx / length) * padFrom;
  const y1 = from.y + (dy / length) * padFrom;
  const x2 = to.x - (dx / length) * padTo;
  const y2 = to.y - (dy / length) * padTo;
  const curve = Math.abs(dy) > 6 ? ` Q ${(x1 + x2) / 2} ${y1} ${x2} ${y2}` : ` L ${x2} ${y2}`;
  return el("path", {
    d: `M ${x1} ${y1}${curve}`,
    class: isHot ? "arc hot" : "arc",
    "marker-end": "url(#arrow)",
  });
}

function effectSummary(effect) {
  const args = Object.entries(effect)
    .filter(([k]) => k !== "id" && k !== "kind")
    .map(([k, v]) => `${k}=${v}`);
  return args.join("  ");
}

function renderEffects() {
  const svg = document.getElementById("effects");
  svg.textContent = "";
  if (!state.result) return;
  const obs = state.result.observation;
  const certificate = state.result.certificate;
  const nodes = [];
  for (const record of obs.records) {
    for (const effect of record.effects || []) {
      nodes.push({ effect, record });
    }
  }
  const musIds = new Set(
    (certificate.minimal_unsatisfiable_set || [])
      .filter((f) => f.fact === "effect")
      .map((f) => f.id)
  );

  const rowHeight = 46;
  const boxWidth = 250;
  const left = 96;
  const height = 20 + nodes.length * rowHeight + 14;
  svg.setAttribute("viewBox", `0 0 ${left + boxWidth + 20} ${height}`);
  svg.setAttribute("height", height);

  const position = new Map();
  nodes.forEach((node, index) => {
    position.set(node.effect.id, { x: left, y: 20 + index * rowHeight });
  });

  const relate = (fromId, toId, label, missing) => {
    const a = position.get(fromId);
    const b = position.get(toId);
    if (!a || !b) return;
    const x = left - 10;
    const bend = Math.max(28, Math.abs(b.y - a.y) * 0.5);
    svg.appendChild(
      el("path", {
        d: `M ${x} ${a.y + 15} C ${x - bend} ${a.y + 15}, ${x - bend} ${b.y + 15}, ${x} ${b.y + 15}`,
        class: missing ? "rel missing" : "rel",
      })
    );
    svg.appendChild(
      el("text", {
        x: 6,
        y: (a.y + b.y) / 2 + 15,
        class: missing ? "rel-label missing" : "rel-label",
      }, label)
    );
  };

  for (const edge of obs.edges || []) relate(edge.from, edge.to, edge.type, false);

  for (const failure of state.result.outcome.failures || []) {
    if (failure.reason !== "obligation_unmet") continue;
    const target = nodes.find((n) => n.effect.kind === failure.target);
    if (target) relate(failure.effect, target.effect.id, failure.relation + " absent", true);
  }

  nodes.forEach((node) => {
    const spot = position.get(node.effect.id);
    const classes = ["effect"];
    if (musIds.has(node.effect.id)) classes.push("mus");
    svg.appendChild(
      el("rect", {
        x: spot.x,
        y: spot.y,
        width: boxWidth,
        height: 32,
        class: classes.join(" "),
      })
    );
    svg.appendChild(
      el("text", { x: spot.x + 10, y: spot.y + 14, class: "label" }, node.effect.kind)
    );
    svg.appendChild(
      el(
        "text",
        { x: spot.x + 10, y: spot.y + 26, class: "label sub" },
        effectSummary(node.effect)
      )
    );
    svg.appendChild(
      el(
        "text",
        { x: spot.x + boxWidth - 8, y: spot.y + 14, class: "label sub", "text-anchor": "end" },
        node.record.step || node.record.plane
      )
    );
  });
}

function renderVerdict() {
  const banner = document.getElementById("verdict");
  const word = banner.querySelector(".word");
  const detail = banner.querySelector(".detail");
  if (!state.result) {
    banner.className = "verdict";
    word.textContent = "—";
    detail.textContent = "";
    return;
  }
  const outcome = state.result.outcome;
  const accepted = outcome.verdict === "accept";
  banner.className = "verdict " + (accepted ? "accept" : "reject");
  word.textContent = accepted ? "ACCEPT" : "REJECT";
  const parts = [`k=${outcome.bound}`, `slack=${outcome.slack}`, `${outcome.states_explored} states`];
  if (state.result.robust === true) parts.unshift("robust: holds at maximum slack");
  if (state.result.robust === false) parts.unshift("explainable by unobserved steps");
  detail.textContent = parts.join(" · ");
}

function renderExplain() {
  const panel = document.getElementById("explain");
  const title = document.getElementById("explain-title");
  panel.textContent = "";
  if (!state.result) return;
  const { outcome, certificate } = state.result;

  if (outcome.verdict === "accept") {
    title.textContent = "Witness path";
    const list = html("ol", "steps");
    (outcome.witness || []).forEach((step, index) => {
      const item = html("li", step.observed ? "" : "unobserved");
      const bindings = Object.entries(step.bindings || {})
        .filter(([k]) => !k.startsWith("_"))
        .map(([k, v]) => `${k}=${v}`)
        .join(" ");
      item.textContent =
        `${step.transition} · ${step.principal}` +
        (step.observed ? ` [${step.record}]` : " [unobserved]") +
        (bindings ? ` ${bindings}` : "");
      if (index === state.playhead) item.style.color = "var(--focus)";
      list.appendChild(item);
    });
    panel.appendChild(list);
    return;
  }

  title.textContent = "Minimal unsatisfiable set";
  const facts = certificate.minimal_unsatisfiable_set || [];
  if (facts.length) {
    const list = html("ul", "facts");
    for (const fact of facts) {
      const item = html("li");
      if (fact.fact === "effect") {
        item.textContent = `${fact.kind}(${Object.entries(fact.args)
          .map(([k, v]) => `${k}=${v}`)
          .join(", ")})`;
      } else if (fact.fact === "step") {
        item.textContent = `${fact.principal} performed \`${fact.step}\``;
      } else {
        item.textContent = `${fact.relation}(${fact.from} -> ${fact.to})`;
      }
      list.appendChild(item);
    }
    panel.appendChild(list);
  }
  for (const note of certificate.notes || []) {
    panel.appendChild(html("p", "note", note));
  }
  for (const failure of certificate.failed_obligations || []) {
    panel.appendChild(html("p", "fail", failure));
  }
}

function renderCertificate() {
  const kv = document.getElementById("cert-kv");
  const json = document.getElementById("cert-json");
  kv.textContent = "";
  json.textContent = "";
  if (!state.result) return;
  const certificate = state.result.certificate;
  const rows = [
    ["workflow", certificate.workflow],
    ["spec", certificate.spec_hash.slice(0, 26) + "…"],
    ["run", certificate.run_id],
    ["observation", certificate.observation_hash.slice(0, 26) + "…"],
    ["bound", `k=${certificate.bound}, slack=${certificate.slack}`],
    ["oracle calls", String(certificate.mus_oracle_calls)],
  ];
  for (const [key, value] of rows) {
    kv.appendChild(html("dt", null, key));
    kv.appendChild(html("dd", null, value));
  }
}

function stopPlayback() {
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
  document.getElementById("play").textContent = "Play witness";
}

function startPlayback() {
  const witness = state.result && state.result.outcome.witness;
  if (!witness || !witness.length) return;
  stopPlayback();
  state.playhead = -1;
  document.getElementById("play").textContent = "Stop";
  state.timer = setInterval(() => {
    state.playhead += 1;
    if (state.playhead >= witness.length) {
      stopPlayback();
      state.playhead = witness.length - 1;
    }
    renderNet();
    renderExplain();
  }, 750);
}

async function selectRun(id) {
  stopPlayback();
  state.current = id;
  state.playhead = -1;
  for (const button of document.querySelectorAll(".run")) {
    button.setAttribute("aria-current", String(button.dataset.id === id));
  }
  state.result = await api(`/api/runs/${id}?slack=${state.slack}`);
  const witness = state.result.outcome.witness;
  state.playhead = witness ? witness.length - 1 : -1;
  document.getElementById("play").disabled = !witness;
  renderVerdict();
  renderNet();
  renderEffects();
  renderExplain();
  renderCertificate();
}

async function loadPermissiveness() {
  const button = document.getElementById("perm");
  button.disabled = true;
  button.textContent = "Measuring…";
  try {
    const data = await api("/api/permissiveness?depth=9");
    const body = document.getElementById("perm-rows");
    body.textContent = "";
    const peak = Math.max(...data.rows.map((r) => r.shapes), 1);
    for (const row of data.rows) {
      const tr = document.createElement("tr");
      tr.appendChild(html("td", "d", `k=${row.depth}`));
      const bar = document.createElement("td");
      const span = html("span", "bar");
      span.style.width = `${Math.max(1, (row.shapes / peak) * 100)}%`;
      bar.appendChild(span);
      tr.appendChild(bar);
      tr.appendChild(html("td", "n", row.shapes + (row.truncated ? "+" : "")));
      body.appendChild(tr);
    }
    document.getElementById("perm-panel").hidden = false;
    button.textContent = "Measure permissiveness";
  } catch (error) {
    button.textContent = "Measurement failed";
  }
  button.disabled = false;
}

async function boot() {
  state.spec = await api("/api/spec");
  document.getElementById("spec-line").textContent =
    `${state.spec.workflow}@sha256:${state.spec.hash.slice(0, 12)}`;
  document.getElementById("lint-line").textContent = state.spec.sound
    ? `${state.spec.spec.places.length} places · ${state.spec.spec.transitions.length} transitions · spec sound`
    : "specification is unsound";

  const runs = await api("/api/runs");
  state.runs = runs.runs;
  const rail = document.getElementById("runs");
  for (const run of state.runs) {
    const button = html("button", "run");
    button.dataset.id = run.id;
    button.appendChild(html("span", "id", run.id));
    button.appendChild(
      html("span", "meta", `${run.records} records · ${run.effects} effects · ${run.edges} edges`)
    );
    button.addEventListener("click", () => selectRun(run.id));
    rail.appendChild(button);
  }

  document.getElementById("slack").addEventListener("input", (event) => {
    state.slack = Number(event.target.value);
    document.getElementById("slack-value").textContent = String(state.slack);
    if (state.current) selectRun(state.current);
  });
  document.getElementById("play").addEventListener("click", () => {
    if (state.timer) stopPlayback();
    else startPlayback();
  });
  document.getElementById("perm").addEventListener("click", loadPermissiveness);
  document.getElementById("download").addEventListener("click", async () => {
    if (!state.current) return;
    const signed = await api(`/api/runs/${state.current}/certificate?slack=${state.slack}`);
    document.getElementById("cert-json").textContent = JSON.stringify(signed, null, 2);
  });

  renderNet();
  if (state.runs.length) selectRun(state.runs[0].id);
}

boot();
