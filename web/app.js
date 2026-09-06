const SVG = "http://www.w3.org/2000/svg";

const COL = 194;
const ROW = 96;
const PLACE_R = 23;
const TW = 148;
const TH = 36;
const CONSUME_MS = 480;
const PRODUCE_MS = 480;
const SETTLE_MS = 240;

const CATALOG = [
  { group: "Required demonstrations", id: "case1", label: "Legitimate release" },
  { group: "Required demonstrations", id: "case2", label: "Malicious, every step valid" },
  { group: "Required demonstrations", id: "case3", label: "Unusual but permitted" },
  { group: "Real incident", id: "attack-capjs", label: "cap-js, stolen token" },
  { group: "Real incident", id: "attack-capjs-provenance", label: "Same run, real provenance" },
  { group: "Held-out attacks", id: "attack-forged-provenance", label: "Forged provenance link" },
  { group: "Held-out attacks", id: "attack-self-approval", label: "Self-issued approval" },
];

const state = {
  spec: null,
  runs: [],
  current: null,
  result: null,
  slack: 0,
  playhead: -1,
  firing: null,
  netSpec: null,
  onboarded: null,
  showBlocked: false,
  running: false,
  cancel: 0,
  arcs: new Map(),
};

const el = (tag, attrs, text) => {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
};

const html = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const reducedMotion = () =>
  window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

async function api(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

let layoutCache = null;

function layoutNet(spec) {
  if (layoutCache && layoutCache.spec === spec) return layoutCache.value;
  const BIG = 1e9;
  const pr = {};
  const tr = {};
  for (const p of spec.places) pr[p.id] = p.tokens && p.tokens.length ? 0 : BIG;
  for (let pass = 0; pass < spec.transitions.length + 2; pass++) {
    for (const t of spec.transitions) {
      const inputs = t.consumes.map((p) => pr[p] ?? BIG);
      tr[t.id] = inputs.length ? Math.max(...inputs) : 0;
    }
    for (const t of spec.transitions) {
      if (tr[t.id] >= BIG) continue;
      for (const p of t.produces) pr[p] = Math.min(pr[p] ?? BIG, tr[t.id] + 1);
    }
  }
  const consumed = new Set();
  for (const t of spec.transitions) for (const p of t.consumes) consumed.add(p);
  for (const p of spec.places) {
    if (consumed.has(p.id)) continue;
    const producers = spec.transitions.filter((t) => t.produces.includes(p.id));
    if (producers.length) pr[p.id] = Math.max(...producers.map((t) => tr[t.id])) + 1;
  }

  const nodes = new Map();
  for (const p of spec.places)
    nodes.set("p:" + p.id, { key: "p:" + p.id, kind: "place", id: p.id, data: p, column: (pr[p.id] ?? 0) * 2 });
  for (const t of spec.transitions)
    nodes.set("t:" + t.id, { key: "t:" + t.id, kind: "transition", id: t.id, data: t, column: (tr[t.id] ?? 0) * 2 + 1 });

  const pred = new Map();
  const succ = new Map();
  for (const n of nodes.values()) { pred.set(n.key, []); succ.set(n.key, []); }
  for (const t of spec.transitions) {
    for (const p of t.consumes) {
      if (!nodes.has("p:" + p)) continue;
      pred.get("t:" + t.id).push("p:" + p);
      succ.get("p:" + p).push("t:" + t.id);
    }
    for (const p of t.produces) {
      if (!nodes.has("p:" + p)) continue;
      pred.get("p:" + p).push("t:" + t.id);
      succ.get("t:" + t.id).push("p:" + p);
    }
  }

  const columns = new Map();
  for (const n of nodes.values()) {
    if (!columns.has(n.column)) columns.set(n.column, []);
    columns.get(n.column).push(n.key);
  }
  const order = [...columns.keys()].sort((a, b) => a - b);
  const row = new Map();
  const reindex = () => order.forEach((c) => columns.get(c).forEach((k, i) => row.set(k, i)));
  reindex();
  const bary = (k, nb) => {
    const v = nb.get(k).map((n) => row.get(n)).filter((x) => x !== undefined);
    return v.length ? v.reduce((a, b) => a + b, 0) / v.length : row.get(k);
  };
  for (let sweep = 0; sweep < 6; sweep++) {
    const fwd = sweep % 2 === 0;
    for (const c of fwd ? order : [...order].reverse()) {
      columns.get(c).sort((a, b) => bary(a, fwd ? pred : succ) - bary(b, fwd ? pred : succ));
      reindex();
    }
  }

  let maxRows = 1;
  order.forEach((c) => (maxRows = Math.max(maxRows, columns.get(c).length)));
  order.forEach((c) => {
    const keys = columns.get(c);
    const off = (maxRows - keys.length) / 2;
    keys.forEach((k, i) => {
      const n = nodes.get(k);
      n.x = 96 + (c / 2) * COL;
      n.y = 58 + (i + off) * ROW;
    });
  });
  const value = { nodes, width: 96 + (Math.max(...order) / 2) * COL + 110, height: 58 + maxRows * ROW + 78 };
  layoutCache = { spec, value };
  return value;
}

function markingAt(spec, steps, upto) {
  const m = {};
  for (const p of spec.places) m[p.id] = (p.tokens || []).length;
  for (let i = 0; i <= upto && steps && i < steps.length; i++) {
    const t = spec.transitions.find((x) => x.id === steps[i].transition);
    if (!t) continue;
    for (const p of t.consumes) m[p] = Math.max(0, (m[p] || 0) - 1);
    for (const p of t.produces) m[p] = (m[p] || 0) + 1;
  }
  return m;
}

const isBack = (a, b) => b.x < a.x - 1;

function arcPath(from, to) {
  if (isBack(from, to)) {
    const y1 = from.y + (from.kind === "place" ? PLACE_R : TH / 2);
    const y2 = to.y + (to.kind === "place" ? PLACE_R : TH / 2);
    const drop = 46 + Math.abs(to.x - from.x) * 0.06;
    return `M ${from.x} ${y1} C ${from.x} ${y1 + drop}, ${to.x} ${y2 + drop}, ${to.x} ${y2}`;
  }
  const dx = to.x - from.x, dy = to.y - from.y;
  const len = Math.hypot(dx, dy) || 1;
  const pf = from.kind === "place" ? PLACE_R + 2 : TW / 2 + 3;
  const pt = to.kind === "place" ? PLACE_R + 6 : TW / 2 + 7;
  const x1 = from.x + (dx / len) * pf, y1 = from.y + (dy / len) * pf;
  const x2 = to.x - (dx / len) * pt, y2 = to.y - (dy / len) * pt;
  const mx = (x1 + x2) / 2;
  return Math.abs(dy) < 4 ? `M ${x1} ${y1} L ${x2} ${y2}` : `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
}

function steps() {
  if (!state.result) return [];
  const o = state.result.outcome;
  return o.witness || o.explained || [];
}

function renderNet() {
  const svg = document.getElementById("net");
  svg.textContent = "";
  state.arcs.clear();
  if (!state.spec) return;
  const spec = state.netSpec || state.spec.spec;
  const { nodes, width, height } = layoutNet(spec);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("preserveAspectRatio", "xMidYMid meet");

  const defs = el("defs");
  const cs = getComputedStyle(document.documentElement);
  const tok = (n, fallback) => (cs.getPropertyValue(n).trim() || fallback);
  for (const [id, fill] of [
    ["a", tok("--arc", "#39414b")],
    ["ah", tok("--accent", "#4493f8")],
    ["ad", tok("--reject", "#f85149")],
  ]) {
    const m = el("marker", { id, viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "6", markerHeight: "6", orient: "auto-start-reverse" });
    m.appendChild(el("path", { d: "M 0 0 L 10 5 L 0 10 z", fill }));
    defs.appendChild(m);
  }
  svg.appendChild(defs);

  const path = steps();
  const done = new Set();
  for (let i = 0; i <= state.playhead && i < path.length; i++) done.add(path[i].transition);

  const activeStep = state.firing || (state.playhead >= 0 && state.playhead < path.length ? path[state.playhead] : null);
  const activeId = activeStep ? activeStep.transition : null;
  const blocked = state.result && state.result.outcome.blocked;
  const blockedId = state.showBlocked && blocked ? blocked.step : null;

  const hot = new Set();
  const dead = new Set();
  const mark = (id, set) => {
    const t = spec.transitions.find((x) => x.id === id);
    if (!t) return;
    t.consumes.forEach((p) => set.add(p + ">" + id));
    t.produces.forEach((p) => set.add(id + ">" + p));
  };
  if (activeId) mark(activeId, hot);
  if (blockedId) mark(blockedId, dead);

  for (const t of spec.transitions) {
    const box = nodes.get("t:" + t.id);
    const draw = (from, to, key) => {
      const d = arcPath(from, to);
      state.arcs.set(key, d);
      const cls = ["arc"];
      if (isBack(from, to)) cls.push("back");
      if (dead.has(key)) cls.push("dead");
      else if (hot.has(key)) cls.push("hot");
      svg.appendChild(el("path", { d, class: cls.join(" "), "marker-end": dead.has(key) ? "url(#ad)" : hot.has(key) ? "url(#ah)" : "url(#a)" }));
    };
    for (const p of t.consumes) { const pl = nodes.get("p:" + p); if (pl) draw(pl, box, p + ">" + t.id); }
    for (const p of t.produces) { const pl = nodes.get("p:" + p); if (pl) draw(box, pl, t.id + ">" + p); }
  }

  const m = markingAt(spec, path, state.playhead);
  for (const n of nodes.values()) {
    if (n.kind === "place") {
      const count = m[n.id] || 0;
      const cls = ["place"];
      if (count > 0) cls.push("marked");
      if ((spec.final || []).includes(n.id)) cls.push("final");
      svg.appendChild(el("circle", { cx: n.x, cy: n.y, r: PLACE_R, class: cls.join(" ") }));
      const shown = Math.min(count, 3);
      for (let i = 0; i < shown; i++)
        svg.appendChild(el("circle", { cx: n.x - (shown - 1) * 4.5 + i * 9, cy: n.y, r: 3.4, class: "token" }));
      if (count > 3) svg.appendChild(el("text", { x: n.x, y: n.y + 4, class: "lbl tiny", "text-anchor": "middle" }, "x" + count));
      svg.appendChild(el("text", { x: n.x, y: n.y + PLACE_R + 16, class: "lbl sub", "text-anchor": "middle" }, n.id));
    } else {
      const cls = ["transition"];
      if (done.has(n.id)) cls.push("done");
      if (activeId === n.id) { cls.push("active"); if (activeStep && !activeStep.observed) cls.push("unobserved"); }
      if (blockedId === n.id) cls.push("blocked");
      svg.appendChild(el("rect", { x: n.x - TW / 2, y: n.y - TH / 2, width: TW, height: TH, rx: 6, class: cls.join(" ") }));
      svg.appendChild(el("text", { x: n.x, y: n.y - 1, class: n.id.length > 21 ? "lbl tiny" : "lbl", "text-anchor": "middle" }, n.id));
      svg.appendChild(el("text", { x: n.x, y: n.y + 12, class: "lbl sub", "text-anchor": "middle" }, n.data.principal));
    }
  }
}

function flowAlong(keys, dur, delay) {
  if (reducedMotion()) return;
  const svg = document.getElementById("net");
  for (const key of keys) {
    const d = state.arcs.get(key);
    if (!d) continue;
    const dot = el("circle", { r: 4.6, class: "flow-dot", opacity: "0" });
    dot.appendChild(el("set", { attributeName: "opacity", to: "1", begin: `${delay}ms`, dur: `${dur}ms`, fill: "remove" }));
    dot.appendChild(el("animateMotion", { dur: `${dur}ms`, begin: `${delay}ms`, path: d, fill: "freeze", calcMode: "spline", keyTimes: "0;1", keySplines: "0.4 0 0.2 1" }));
    svg.appendChild(dot);
  }
}

async function simulate() {
  const path = steps();
  if (!path.length) return;
  const btn = document.getElementById("play");
  const token = ++state.cancel;
  state.running = true;
  btn.textContent = "Stop";
  btn.classList.add("running");

  const spec = state.netSpec || state.spec.spec;
  state.playhead = -1;
  state.firing = null;
  state.showBlocked = false;
  renderNet();
  renderTrace();
  await wait(280);

  for (let i = 0; i < path.length; i++) {
    if (token !== state.cancel) break;
    const step = path[i];
    const t = spec.transitions.find((x) => x.id === step.transition);
    state.playhead = i - 1;
    state.firing = step;
    renderNet();
    renderTrace();
    if (t) {
      flowAlong(t.consumes.map((p) => p + ">" + t.id), CONSUME_MS, 0);
      flowAlong(t.produces.map((p) => t.id + ">" + p), PRODUCE_MS, CONSUME_MS + 110);
    }
    await wait(reducedMotion() ? 420 : CONSUME_MS + PRODUCE_MS + SETTLE_MS);
    if (token !== state.cancel) break;
    state.playhead = i;
    state.firing = null;
    renderNet();
    renderTrace();
    await wait(140);
  }

  if (token === state.cancel) {
    state.playhead = path.length - 1;
    state.firing = null;
    state.showBlocked = true;
    renderNet();
    renderTrace();
    stopSim();
  }
}

function stopSim() {
  state.cancel += 1;
  state.running = false;
  state.firing = null;
  const btn = document.getElementById("play");
  btn.textContent = "Simulate run";
  btn.classList.remove("running");
}

function renderCompare() {
  const box = document.getElementById("compare");
  if (!state.result || !state.result.permission) { box.hidden = true; return; }
  box.hidden = false;
  const perm = state.result.permission;
  const reach = state.result.outcome.verdict === "accept";
  const legacy = document.getElementById("legacy-v");
  const mr = document.getElementById("mr-v");
  legacy.textContent = perm.allowed ? "ALLOWED" : "DENIED";
  legacy.className = perm.allowed ? "pass" : "fail";
  mr.textContent = reach ? "ACCEPT" : "REJECT";
  mr.className = reach ? "pass" : "fail";
}

function renderRibbon() {
  const host = document.getElementById("ribbon");
  host.textContent = "";
  if (!state.result) return;
  const o = state.result.outcome;
  const ok = o.verdict === "accept";
  const path = ok ? (o.witness || []) : (o.explained || []);

  const stepEl = (label, who, cls, icon) => {
    const s = html("div", "step " + cls);
    s.appendChild(html("div", "icon", icon));
    s.appendChild(html("div", "name", label));
    if (who) s.appendChild(html("div", "who", who));
    return s;
  };
  const link = (cls) => html("div", "link " + cls);

  let first = true;
  for (const step of path) {
    const node = html("div", "node");
    if (!first) node.appendChild(link("ok"));
    first = false;
    node.appendChild(stepEl(step.transition, step.observed ? "" : "assumed", "ok", "✓"));
    host.appendChild(node);
  }

  if (!ok) {
    // the step or effect that made it impossible
    const node = html("div", "node");
    if (!first) node.appendChild(link("bad"));
    const cause = html("div", "cause");
    cause.appendChild(html("div", "icon", "✗"));
    if (o.blocked) {
      cause.appendChild(html("div", "name", o.blocked.step));
      cause.appendChild(html("div", "who", "cannot happen here"));
    } else {
      const core = (state.result.certificate.minimal_unsatisfiable_set || [])
        .find((f) => f.fact === "effect");
      cause.appendChild(html("div", "name", core ? core.kind : "impossible outcome"));
      cause.appendChild(html("div", "who", "nothing in the pipeline caused this"));
    }
    node.appendChild(cause);
    host.appendChild(node);
  }
}

function renderVerdict() {
  const box = document.getElementById("verdict");
  const word = box.querySelector(".word");
  const sum = box.querySelector(".sum");
  let facts = box.querySelector(".facts");
  if (!facts) { facts = html("span", "facts"); box.appendChild(facts); }
  if (!state.result) {
    box.className = "verdict";
    word.textContent = "Ready";
    sum.textContent = "Select a run.";
    facts.textContent = "";
    return;
  }
  const o = state.result.outcome;
  const ok = o.verdict === "accept";
  box.className = "verdict " + (ok ? "accept" : "reject");
  word.textContent = ok ? "Accepted" : "Rejected";
  if (ok) {
    sum.textContent = `Every observed step and effect is explained by a legal path through the workflow.`;
  } else if (o.blocked) {
    sum.textContent = `Legal up to ${o.explained.length} step${o.explained.length === 1 ? "" : "s"}, then “${o.blocked.step}” cannot happen.`;
  } else {
    sum.textContent = `Every step is legal, but an observed effect has no producing transition.`;
  }
  const bits = [`k=${o.bound}`, `slack=${o.slack}`, `${o.states_explored} states`];
  if (state.result.robust === true) bits.unshift("robust");
  if (state.result.robust === false) bits.unshift("logging-dependent");
  facts.textContent = bits.join("  ");
}

function renderTrace() {
  const title = document.getElementById("trace-title");
  const host = document.getElementById("trace");
  host.textContent = "";
  if (!state.result) return;
  const o = state.result.outcome;
  const path = steps();
  const ok = o.verdict === "accept";
  title.textContent = ok
    ? `Witness path — ${path.length} steps`
    : `Longest legal prefix — ${o.explained.filter((s) => s.observed).length} of ${o.observed_steps} observed steps`;

  const list = html("ol", "trace");
  path.forEach((step, i) => {
    const cls = [];
    if (!step.observed) cls.push("unobserved");
    if (state.firing ? state.firing === step : i === state.playhead && state.running) cls.push("now");
    const li = html("li", cls.join(" "));
    li.appendChild(html("span", "mark", "✓"));
    const body = html("div");
    const what = html("div", "what", step.transition);
    const bind = Object.entries(step.bindings || {})
      .filter(([k]) => !k.startsWith("_"))
      .map(([k, v]) => `${k}=${v}`)
      .join("  ");
    body.appendChild(what);
    body.appendChild(
      html("div", "who", `${step.principal}  ${step.observed ? "[" + step.record + "]" : "[unlogged]"}${bind ? "  " + bind : ""}`)
    );
    li.appendChild(body);
    list.appendChild(li);
  });

  if (!ok && o.blocked) {
    const li = html("li", "blocked");
    li.appendChild(html("span", "mark", "✗"));
    const body = html("div");
    body.appendChild(html("div", "what", o.blocked.step));
    body.appendChild(html("div", "who", `${o.blocked.principal}  [${o.blocked.record}]  cannot fire here`));
    li.appendChild(body);
    list.appendChild(li);
  }

  if (!path.length && !(o.blocked)) host.appendChild(html("p", "empty", "Nothing was explained. The observation was rejected before the search began."));
  else host.appendChild(list);
}

function whyOverview() {
  if (!state.result) return { text: "Select a run.", cls: "" };
  const { outcome: o, certificate: c } = state.result;
  if (o.verdict === "accept") {
    return { text: `Reachable: a legal path of ${(o.witness||[]).length} steps explains the run.`, cls: "ok" };
  }
  // prefer the sharpest one-liner: a digest mismatch, else the blocked step, else unmatched effect
  const mismatch = (o.failures || []).find((f) => f.reason === "effect_arg_mismatch");
  if (mismatch) return { text: `${mismatch.step}: published ${mismatch.observed} ≠ built ${mismatch.expected.replace(/^\$\w+ = /, "")}`, cls: "bad" };
  if (o.blocked) return { text: `Blocked at ${o.blocked.step}: not reachable in the declared workflow.`, cls: "bad" };
  const eff = (c.minimal_unsatisfiable_set || []).find((f) => f.fact === "effect");
  if (eff) return { text: `${eff.kind} has no producing step in the workflow.`, cls: "bad" };
  return { text: "Rejected: no legal execution produces this run.", cls: "bad" };
}

function renderWhy() {
  const ov = whyOverview();
  const overview = document.getElementById("why-overview");
  overview.textContent = ov.text;
  overview.className = "overview " + ov.cls;
  const title = document.getElementById("why-title");
  const host = document.getElementById("why");
  host.textContent = "";
  if (!state.result) return;
  const { outcome: o, certificate: c } = state.result;

  if (o.verdict === "accept") {
    title.textContent = "Why it is legal";
    host.appendChild(html("h3", null, "A legal path exists"));
    host.appendChild(
      html("p", null, "The workflow permits this exact sequence. Unusual is not the same as impossible, so the run is accepted even if it has never occurred before.")
    );
    host.appendChild(html("p", "mono", o.witness.map((s) => s.transition).join(" → ")));
    if (o.slack > 0) {
      const un = o.witness.filter((s) => !s.observed).length;
      if (un) host.appendChild(html("p", null, `${un} step(s) in this path were never logged. They are assumed because the rest of the run only makes sense if they happened.`));
    }
    return;
  }

  title.textContent = "Why it is impossible";
  if (o.blocked) {
    host.appendChild(html("h3", null, `Blocked at ${o.blocked.step}`));
    host.appendChild(html("p", null, `Everything before this point is legal. No accepting path of the declared workflow continues past it.`));
  } else {
    host.appendChild(html("h3", null, "An effect has no cause"));
    host.appendChild(html("p", null, "Every recorded step is legal on its own, but the run produced an effect that no transition of this workflow could have emitted."));
  }

  const core = c.minimal_unsatisfiable_set || [];
  if (core.length) {
    host.appendChild(html("h3", null, `Smallest impossible set — ${core.length} fact${core.length === 1 ? "" : "s"}`));
    const ul = html("ul", "core");
    for (const f of core) {
      const li = html("li");
      if (f.fact === "effect") li.textContent = `${f.kind}(${Object.entries(f.args).map(([k, v]) => `${k}=${v}`).join(", ")})`;
      else if (f.fact === "step") li.textContent = `${f.principal} performed ${f.step}`;
      else li.textContent = `${f.relation}(${f.from} → ${f.to})`;
      ul.appendChild(li);
    }
    host.appendChild(ul);
    host.appendChild(html("p", null, `Remove any one of these and the run becomes explainable. Verified with ${c.mus_oracle_calls} checks.`));
  }

  for (const n of c.notes || []) host.appendChild(html("p", "note", n));
  if ((c.failed_obligations || []).length) {
    host.appendChild(html("h3", null, "Broken rule"));
    for (const f of c.failed_obligations) host.appendChild(html("p", "mono", f));
  }
  host.appendChild(
    html("p", null, state.result.robust === true
      ? "This holds at maximum slack: no amount of assumed missing logging explains it."
      : "This depends on the logging-completeness assumption stated above.")
  );
}

function renderEffects() {
  const svg = document.getElementById("effects");
  svg.textContent = "";
  if (!state.result) return;
  const obs = state.result.observation;
  const c = state.result.certificate;
  const nodes = [];
  for (const r of obs.records) for (const e of r.effects || []) nodes.push({ effect: e, record: r });
  const core = new Set((c.minimal_unsatisfiable_set || []).filter((f) => f.fact === "effect").map((f) => f.id));

  const RH = 52, BW = 250, LEFT = 100;
  const height = 16 + nodes.length * RH + 10;
  svg.setAttribute("viewBox", `0 0 ${LEFT + BW + 14} ${height}`);
  svg.setAttribute("height", height);
  const pos = new Map();
  nodes.forEach((n, i) => pos.set(n.effect.id, { x: LEFT, y: 14 + i * RH }));

  const relate = (from, to, label, missing) => {
    const a = pos.get(from), b = pos.get(to);
    if (!a || !b) return;
    const x = LEFT - 8;
    const bend = Math.min(70, 26 + Math.abs(b.y - a.y) * 0.42);
    svg.appendChild(el("path", { d: `M ${x} ${a.y + 17} C ${x - bend} ${a.y + 17}, ${x - bend} ${b.y + 17}, ${x} ${b.y + 17}`, class: missing ? "rel missing" : "rel" }));
    svg.appendChild(el("text", { x: 5, y: (a.y + b.y) / 2 + 20, class: missing ? "rel-lbl missing" : "rel-lbl" }, label));
  };
  for (const e of obs.edges || []) relate(e.from, e.to, e.type, false);
  for (const f of state.result.outcome.failures || []) {
    if (f.reason !== "obligation_unmet") continue;
    const t = nodes.find((n) => n.effect.kind === f.target);
    if (t) relate(f.effect, t.effect.id, f.relation + " missing", true);
  }

  nodes.forEach((n) => {
    const s = pos.get(n.effect.id);
    const cls = ["effect"];
    if (core.has(n.effect.id)) cls.push("core");
    svg.appendChild(el("rect", { x: s.x, y: s.y, width: BW, height: 36, rx: 6, class: cls.join(" ") }));
    svg.appendChild(el("text", { x: s.x + 11, y: s.y + 15, class: "lbl" }, n.effect.kind));
    const args = Object.entries(n.effect).filter(([k]) => k !== "id" && k !== "kind").map(([k, v]) => `${k}=${v}`).join("  ");
    svg.appendChild(el("text", { x: s.x + 11, y: s.y + 28, class: "lbl sub" }, args));
    svg.appendChild(el("text", { x: s.x + BW - 9, y: s.y + 15, class: "lbl sub", "text-anchor": "end" }, n.record.step || n.record.plane));
  });
}

function renderCert() {
  const kv = document.getElementById("cert");
  kv.textContent = "";
  document.getElementById("cert-json").textContent = "";
  if (!state.result) return;
  const c = state.result.certificate;
  const rows = [
    ["verdict", c.verdict],
    ["workflow", c.workflow],
    ["spec", c.spec_hash.slice(0, 22) + "..."],
    ["run", c.run_id],
    ["observation", c.observation_hash.slice(0, 22) + "..."],
    ["bound", `k=${c.bound}, slack=${c.slack}`],
  ];
  for (const [k, v] of rows) { kv.appendChild(html("dt", null, k)); kv.appendChild(html("dd", null, v)); }
}

async function selectRun(id) {
  stopSim();
  state.current = id;
  state.netSpec = state.spec.spec;
  state.playhead = -1;
  state.showBlocked = true;
  for (const b of document.querySelectorAll(".run")) b.setAttribute("aria-current", String(b.dataset.id === id));
  state.result = await api(`/api/runs/${id}?slack=${state.slack}`);
  state.playhead = steps().length - 1;
  document.getElementById("play").disabled = steps().length === 0;
  renderVerdict();
  renderCompare();
  renderRibbon();
  renderNet();
  renderTrace();
  renderWhy();
  renderEffects();
  renderCert();
}

async function loadPerm() {
  const btn = document.getElementById("perm");
  btn.disabled = true;
  btn.textContent = "Measuring";
  try {
    const data = await api("/api/permissiveness?depth=9");
    const body = document.getElementById("perm-rows");
    body.textContent = "";
    const peak = Math.max(...data.rows.map((r) => r.shapes), 1);
    for (const row of data.rows) {
      const tr = document.createElement("tr");
      tr.appendChild(html("td", "d", `k=${row.depth}`));
      const cell = document.createElement("td");
      if (row.shapes > 0) {
        const bar = html("span", "bar");
        bar.style.width = `${Math.max(2, (row.shapes / peak) * 100)}%`;
        cell.appendChild(bar);
      }
      tr.appendChild(cell);
      tr.appendChild(html("td", "n", row.shapes === 0 ? "none" : row.shapes + (row.truncated ? "+" : "")));
      body.appendChild(tr);
    }
    document.getElementById("perm-panel").hidden = false;
    btn.textContent = "Measure permissiveness";
  } catch (e) {
    btn.textContent = "Measurement failed";
  }
  btn.disabled = false;
}

function setPane(side, visible) {
  document.body.classList.toggle(side === "left" ? "hide-left" : "hide-right", !visible);
  document.getElementById(side === "left" ? "tl" : "tr").setAttribute("aria-pressed", String(visible));
}

function togglePane(side) {
  setPane(side, document.body.classList.contains(side === "left" ? "hide-left" : "hide-right"));
}

function parseRunUrl(url) {
  const m = url.trim().match(/github\.com\/([^/]+)\/([^/]+)\/actions\/runs\/(\d+)/);
  if (m) return { owner: m[1], repo: m[2], id: m[3] };
  const api = url.trim().match(/repos\/([^/]+)\/([^/]+)\/actions\/runs\/(\d+)/);
  if (api) return { owner: api[1], repo: api[2], id: api[3] };
  return null;
}

async function ghFetch(path) {
  const res = await fetch(`https://api.github.com/${path}`, {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (!res.ok) throw new Error(`GitHub API ${res.status} for ${path}`);
  return res.json();
}

function deriveFacts(jobs) {
  // Best-effort: pull a digest per job from step names if the workflow exposes
  // one via an artifact. Real pipelines emit these; when absent, the server
  // simply has no provenance edge to check, which is itself informative.
  const facts = [];
  for (const job of jobs.jobs || []) {
    for (const step of job.steps || []) {
      const name = (step.name || "").toLowerCase();
      if (name.includes("publish") || name.includes("build") || name.includes("test")) {
        facts.push({ step: step.name });
      }
    }
  }
  return facts;
}

async function onboardRepo() {
  const input = document.getElementById("live-url");
  const status = document.getElementById("live-status");
  const btn = document.getElementById("live-onboard");
  const parsed = parseRunUrl(input.value);
  if (!parsed) {
    status.className = "live-status err";
    status.textContent = "Paste a run URL from the repo you want to onboard.";
    return;
  }
  btn.disabled = true;
  status.className = "live-status";
  status.textContent = `Fetching ${parsed.owner}/${parsed.repo}'s workflow...`;
  try {
    // the run object names the workflow file that produced it
    const run = await ghFetch(`repos/${parsed.owner}/${parsed.repo}/actions/runs/${parsed.id}`);
    const path = run.path || ".github/workflows/main.yml";
    const file = await ghFetch(`repos/${parsed.owner}/${parsed.repo}/contents/${path}?ref=${run.head_sha}`);
    const yaml = atob(file.content.replace(/[^A-Za-z0-9+/=]/g, ""));
    const res = await fetch("/api/onboard", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: `${parsed.owner}/${parsed.repo}`, workflow: yaml }),
    });
    const out = await res.json();
    if (!res.ok) throw new Error(out.error || "onboard failed");
    if (out.registered) {
      state.onboarded = `${parsed.owner}/${parsed.repo}`;
      status.className = "live-status ok";
      status.textContent = `Onboarded ${parsed.repo}: ${out.jobs} jobs -> ${out.transitions} transitions, spec sound. Now Verify this run.`;
    } else {
      status.className = "live-status err";
      status.textContent = `Generated spec is not sound: ${(out.diagnostics || [])[0] || "needs manual effect relations"}`;
    }
  } catch (e) {
    status.className = "live-status err";
    status.textContent = String(e.message || e);
  }
  btn.disabled = false;
}

async function verifyLiveRun(hijack) {
  const input = document.getElementById("live-url");
  const status = document.getElementById("live-status");
  const btn = document.getElementById("live-go");
  const parsed = parseRunUrl(input.value);
  if (!parsed) {
    status.textContent = "Paste a URL like github.com/owner/repo/actions/runs/123";
    status.className = "live-status err";
    return;
  }
  btn.disabled = true;
  status.className = "live-status";
  status.textContent = `Fetching run ${parsed.id} from GitHub...`;
  try {
    const base = `repos/${parsed.owner}/${parsed.repo}/actions/runs/${parsed.id}`;
    let [run, jobs] = await Promise.all([ghFetch(base), ghFetch(`${base}/jobs`)]);
    status.textContent = `Verifying ${jobs.jobs.length} jobs...`;
    const facts = deriveFacts(jobs);
    if (hijack) {
      // Simulate a stolen credential: a publish job the pipeline never declares,
      // pushing an artifact no build produced. Works against any workflow.
      const lastTs = (jobs.jobs || []).reduce((a, j) => j.started_at > a ? j.started_at : a, "");
      jobs = { ...jobs, jobs: [...(jobs.jobs || []), {
        id: 999999, name: "publish", conclusion: "success",
        started_at: lastTs || "2026-01-01T00:00:00Z", steps: [],
      }]};
      facts.push({ step: "publish", scope: "registry://prod/hijacked", digest: "sha256:STOLEN00000000" });
    }
    const payload = { run, jobs, facts, slack: 1 };
    if (state.onboarded) payload.spec = state.onboarded;
    const res = await fetch("/api/live", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.error || "verify failed");
    state.current = null;
    for (const b of document.querySelectorAll(".run")) b.setAttribute("aria-current", "false");
    state.result = result;
    state.netSpec = result.spec_def || state.spec.spec;
    state.playhead = steps().length - 1;
    document.getElementById("play").disabled = steps().length === 0;
    renderVerdict();
    renderCompare();
    renderRibbon();
    renderNet();
    renderTrace();
    renderWhy();
    renderEffects();
    renderCert();
    const ok = result.outcome.verdict === "accept";
    status.className = "live-status " + (ok ? "ok" : "err");
    status.textContent = `${parsed.owner}/${parsed.repo} #${parsed.id}: ${ok ? "ACCEPT" : "REJECT"}${hijack ? " (simulated hijack)" : ""}`;
  } catch (e) {
    status.className = "live-status err";
    status.textContent = String(e.message || e);
  }
  btn.disabled = false;
}

async function boot() {
  state.spec = await api("/api/spec");
  const specLine = document.getElementById("spec-line"); if (specLine) specLine.textContent = `${state.spec.workflow}@sha256:${state.spec.hash.slice(0, 12)}`;
  const lint = document.getElementById("lint");
  lint.textContent = state.spec.sound ? "spec sound" : "spec unsound";
  lint.className = state.spec.sound ? "tag ok" : "tag bad";

  const runs = await api("/api/runs");
  const known = new Set(CATALOG.map((c) => c.id));
  const available = new Map(runs.runs.map((r) => [r.id, r]));
  const ordered = CATALOG.filter((c) => available.has(c.id)).map((c) => ({ ...c, run: available.get(c.id) }));
  for (const r of runs.runs) {
    if (!known.has(r.id)) ordered.push({ group: "Other", id: r.id, label: r.id, run: r });
  }
  state.runs = ordered.map((o) => o.run);

  const rail = document.getElementById("runs");
  let lastGroup = null;
  let index = 0;
  for (const entry of ordered) {
    index += 1;
    if (entry.group !== lastGroup) {
      rail.appendChild(html("p", "group", entry.group));
      lastGroup = entry.group;
    }
    const btn = html("button", "run");
    btn.dataset.id = entry.id;
    btn.title = `${entry.id}  (key ${index})`;
    const left = html("div");
    left.appendChild(html("div", "name", entry.label));
    left.appendChild(html("div", "meta", `${entry.run.records} records  ${entry.run.effects} effects  ${entry.run.edges} edges`));
    btn.appendChild(left);
    const chip = html("span", "tag", "");
    btn.appendChild(chip);
    btn.addEventListener("click", () => selectRun(entry.id));
    rail.appendChild(btn);
    api(`/api/runs/${entry.id}?slack=0`)
      .then((r) => {
        const ok = r.outcome.verdict === "accept";
        chip.textContent = ok ? "accept" : "reject";
        chip.className = "tag " + (ok ? "ok" : "bad");
      })
      .catch(() => { chip.textContent = "?"; });
  }

  document.getElementById("slack").addEventListener("input", (e) => {
    state.slack = Number(e.target.value);
    document.getElementById("slack-val").textContent = String(state.slack);
    if (state.current) selectRun(state.current);
  });
  document.getElementById("play").addEventListener("click", () => (state.running ? stopSim() : simulate()));
  document.getElementById("perm").addEventListener("click", loadPerm);
  document.getElementById("tl").addEventListener("click", () => togglePane("left"));
  document.getElementById("tr").addEventListener("click", () => togglePane("right"));
  const setMode = (real) => {
    document.body.classList.toggle("mode-real", real);
    document.getElementById("mode-pre").setAttribute("aria-pressed", String(!real));
    document.getElementById("mode-real").setAttribute("aria-pressed", String(real));
  };
  document.getElementById("mode-pre").addEventListener("click", () => setMode(false));
  document.getElementById("mode-real").addEventListener("click", () => setMode(true));
  document.getElementById("live-go").addEventListener("click", () => verifyLiveRun(false));
  document.getElementById("live-hijack").addEventListener("click", () => verifyLiveRun(true));
  document.getElementById("live-onboard").addEventListener("click", onboardRepo);
  document.getElementById("live-url").addEventListener("keydown", (e) => {
    if (e.key === "Enter") verifyLiveRun(false);
  });
  document.getElementById("sign").addEventListener("click", async () => {
    if (!state.current) return;
    const signed = await api(`/api/runs/${state.current}/certificate?slack=${state.slack}`);
    document.getElementById("cert-json").textContent = JSON.stringify(signed, null, 2);
  });
  document.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT") return;
    if (e.key === "[") togglePane("left");
    if (e.key === "]") togglePane("right");
    if (e.key === " ") { e.preventDefault(); state.running ? stopSim() : simulate(); }
    const n = Number(e.key);
    if (n >= 1 && n <= 9 && state.runs[n - 1]) selectRun(state.runs[n - 1].id);
  });

  renderNet();
  if (state.runs.length) selectRun(state.runs[0].id);
}

boot();
