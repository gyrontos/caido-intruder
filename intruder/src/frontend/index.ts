import type { Caido } from "@caido/sdk-frontend";
import type { API, Events } from "../shared/api";
import type { AttackConfig, AttackMode, PayloadSource, ResultEvent, StatusEvent } from "../shared/types";

export type CaidoSDK = Caido<API, Events>;

/* ---------------------------------- state --------------------------------- */

interface PluginState {
  template: string;
  mode: AttackMode;
  threads: number;
  throttleMs: number;
  maxRequests: number;
  timeoutMs: number;
  encode: boolean;
  saveRequests: boolean;
  payloadSets: PayloadSource[];
}

const DEFAULT_TEMPLATE = [
  "GET /products?id=§1§ HTTP/1.1",
  "Host: example.com",
  "User-Agent: intruder/0.1",
  "Accept: */*",
  "Connection: close",
  "",
].join("\r\n");

const DEFAULT_PAYLOAD_SET: PayloadSource = {
  type: "list",
  items: [
    "1",
    "2",
    "3",
    "1'",
    '1" OR 1=1-- -',
    "1 UNION SELECT 1,2,3-- -",
  ],
};

const STATE_DEFAULTS: PluginState = {
  template: DEFAULT_TEMPLATE,
  mode: "sniper",
  threads: 4,
  throttleMs: 0,
  maxRequests: 10000,
  timeoutMs: 10000,
  encode: false,
  saveRequests: false,
  payloadSets: [DEFAULT_PAYLOAD_SET],
};

let state: PluginState = { ...STATE_DEFAULTS };
let appSdk: CaidoSDK | null = null; // set once in init; helpers use it to persist state

function saveStateSoon() {
  if (!appSdk) return;
  appSdk.storage.set(state).catch((e) => appSdk?.log.error(String(e)));
}

/* --------------------------------- samples -------------------------------- */

const SAMPLES: Array<{ name: string; template: string; payload: PayloadSource }> = [
  {
    name: "IDOR / enumeration (GET param)",
    template: "GET /api/users/§1§ HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
    payload: sampleList(["1001", "1002", "1003", "0", "-1"]),
  },
  {
    name: "Login brute force (JSON body)",
    template:
      'POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{"username":"§USER§","password":"§PASS§"}',
    payload: sampleList(["admin", "root", "test"]),
  },
  {
    name: "Path traversal (query param)",
    template: "GET /download?file=§TRAVERSAL§ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    payload: sampleList(["report.pdf", "../etc/passwd", "..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"]),
  },
  {
    name: "SQL injection (query param)",
    template: "GET /products?id=§SQLI§ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    payload: sampleList(["1", "1'", "1\"", "1 OR 1=1-- -", "1' OR 1=1-- -", "1 UNION SELECT 1,2,3-- -"]),
  },
  {
    name: "Host header virtual-host probe",
    template: "GET / HTTP/1.1\r\nHost: §HOST§\r\nConnection: close\r\n\r\n",
    payload: sampleList(["example.com", "admin.example.com", "localhost", "169.254.169.254"]),
  },
  {
    name: "Numeric ID range (numbers payload)",
    template: "GET /invoice/§ID§ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    payload: { type: "numbers", from: 10000, to: 10050, step: 1, pad: 0 },
  },
  {
    name: "Charset fuzz (parameter value)",
    template: "GET /?value=§FUZZ§ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    payload: { type: "fuzz", charset: "ab'\"<>", minLength: 1, maxLength: 2 },
  },
];

function sampleList(items: string[]): PayloadSource {
  return { type: "list", items };
}

/* ------------------------------- ui helpers ------------------------------- */

function h(tag: string, attrs: Record<string, unknown> = {}, ...children: Array<Node | string>): HTMLElement {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = String(v);
    else if (k === "text") el.textContent = String(v);
    else if (k in el) (el as any)[k] = v;
    else el.setAttribute(k, String(v));
  }
  for (const c of children) el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  return el;
}

function payloadSummary(p: PayloadSource): string {
  switch (p.type) {
    case "list":
      return `list (${p.items.length})`;
    case "numbers":
      return `numbers ${p.from}..${p.to} step ${p.step}`;
    case "fuzz":
      return `fuzz chars ${p.charset.length} len ${p.minLength}-${p.maxLength}`;
  }
}

function wantedSetCount(mode: AttackMode, positionCount: number): number {
  return mode === "sniper" || mode === "battering-ram" ? 1 : Math.max(positionCount, 2);
}

/* ---------------------------------- init ---------------------------------- */

export const init = (sdk: CaidoSDK) => {
  appSdk = sdk;

  state = { ...STATE_DEFAULTS };
  const stored = sdk.storage.get();
  if (stored && typeof stored === "object") {
    for (const [k, v] of Object.entries(stored)) {
      if (k in state) (state as any)[k] = v;
    }
    if (!Array.isArray(state.payloadSets) || state.payloadSets.length === 0) {
      state.payloadSets = [DEFAULT_PAYLOAD_SET];
    }
  }

  /* ------------------------------- commands ------------------------------- */

  sdk.commands.register("intruder-open", {
    name: "Open Intruder",
    group: "Intruder",
    run: () => {
      void sdk.navigation.goTo("/intruder");
    },
  });

  sdk.commands.register("intruder-send-request", {
    name: "Send request to Intruder",
    group: "Intruder",
    when: (ctx) => ctx.type !== "BaseContext",
    run: async (ctx) => {
      let raw: string | undefined;
      if (ctx.type === "RequestContext" || ctx.type === "ResponseContext") {
        raw = (ctx.request as { raw?: string }).raw;
        if (!raw && "id" in ctx.request) {
          raw = await sdk.backend.getRawRequest(String(ctx.request.id));
        }
      } else if (ctx.type === "RequestRowContext") {
        const first = ctx.requests[0];
        if (first) raw = await sdk.backend.getRawRequest(first.id);
      }
      if (!raw) {
        sdk.log.error("No request content available to send to Intruder.");
        return;
      }
      state.template = raw;
      syncTemplateEditor();
      void sdk.navigation.goTo("/intruder");
    },
  });

  sdk.commandPalette.register("intruder-open");
  sdk.commandPalette.register("intruder-send-request");

  /* -------------------------------- events -------------------------------- */

  sdk.backend.onEvent("intruder:result", (ev) => addResultRow(ev));
  sdk.backend.onEvent("intruder:status", (ev) => onStatus(ev));

  /* --------------------------------- page --------------------------------- */

  sdk.navigation.addPage("/intruder", { body: buildPage() });
  sdk.sidebar.registerItem("Intruder", "/intruder", {
    icon: "fas fa-crosshairs",
    group: "Tools",
  });
};

/* ---------------------------------- page ---------------------------------- */

let templateEl: HTMLTextAreaElement | null = null;
let posBarEl: HTMLElement | null = null;
let setsEl: HTMLElement | null = null;
let modeEl: HTMLSelectElement | null = null;
let resultsBodyEl: HTMLElement | null = null;
let statusEl: HTMLElement | null = null;
let resultsCsvRows: string[] = [];
let shownAttackId = "";

const MODE_LABELS: Record<AttackMode, string> = {
  sniper: "Sniper",
  "battering-ram": "Battering ram",
  pitchfork: "Pitchfork",
  "cluster-bomb": "Cluster bomb",
};

const MODE_HINTS: Record<AttackMode, string> = {
  sniper: "Sniper: one payload set, each §position§ attacked in turn with every payload.",
  "battering-ram": "Battering ram: one payload set, the same payload goes into all §positions§ at once.",
  pitchfork: "Pitchfork: one payload list per §position§, lists are paired by index.",
  "cluster-bomb": "Cluster bomb: one payload list per §position§, all combinations are tried (Cartesian product).",
};

function countPositions(template: string): number {
  return Math.floor(template.split("§").length / 2);
}

function buildPage(): HTMLElement {
  const root = h("div", { class: "intruder-root" });

  const style = document.createElement("style");
  style.textContent = CSS;
  root.appendChild(style);

  /* request template toolbar */
  const reqIdInput = h("input", { class: "intruder-input", placeholder: "Request ID", style: "width:90px" }) as HTMLInputElement;
  const sampleSel = h("select", { class: "intruder-input" }) as HTMLSelectElement;
  const firstOpt = h("option", { value: "" }) as HTMLOptionElement;
  firstOpt.textContent = "— sample templates —";
  sampleSel.appendChild(firstOpt);
  for (const s of SAMPLES) {
    const o = h("option", { value: s.name }) as HTMLOptionElement;
    o.textContent = s.name;
    sampleSel.appendChild(o);
  }

  const loadBtn = h("button", { class: "intruder-button", text: "Load by ID" });
  loadBtn.addEventListener("click", () => void loadRequestId(reqIdInput.value));
  const applyBtn = h("button", { class: "intruder-button", text: "Apply sample" });
  applyBtn.addEventListener("click", () => applySample(sampleSel.value));

  const editorHeader = h(
    "div",
    { class: "intruder-toolbar" },
    h("strong", { text: "Request template" }),
    h("span", { class: "intruder-hint", text: "Select text, then click § Mark §." }),
    h("button", { class: "intruder-button", text: "§ Mark §", onclick: () => markSelection() }),
    h("button", { class: "intruder-button", text: "Clear marks", onclick: () => clearMarks() }),
    reqIdInput,
    loadBtn,
    sampleSel,
    applyBtn,
  );

  templateEl = h("textarea", { class: "intruder-template", spellcheck: "false" }) as HTMLTextAreaElement;
  templateEl.value = state.template;
  templateEl.addEventListener("input", () => {
    state.template = templateEl!.value;
    saveStateSoon();
    refreshPositions();
    refreshSetEditors();
  });

  posBarEl = h("div", { class: "intruder-hint", text: "Positions: 0" });

  /* mode + run controls */
  modeEl = h("select", { class: "intruder-input" }) as HTMLSelectElement;
  for (const m of Object.keys(MODE_LABELS) as AttackMode[]) {
    const o = h("option", { value: m }) as HTMLOptionElement;
    o.textContent = MODE_LABELS[m];
    if (m === state.mode) o.selected = true;
    modeEl.appendChild(o);
  }
  modeEl.addEventListener("change", () => {
    state.mode = modeEl!.value as AttackMode;
    const n = countPositions(state.template);
    state.payloadSets = adjustSets(state.payloadSets, wantedSetCount(state.mode, n));
    saveStateSoon();
    refreshSetEditors();
  });

  const encodeBox = h("input", { type: "checkbox" }) as HTMLInputElement;
  encodeBox.checked = state.encode;
  encodeBox.addEventListener("change", () => {
    state.encode = encodeBox.checked;
    saveStateSoon();
  });

  const saveBox = h("input", { type: "checkbox" }) as HTMLInputElement;
  saveBox.checked = state.saveRequests;
  saveBox.addEventListener("change", () => {
    state.saveRequests = saveBox.checked;
    saveStateSoon();
  });

  const numbersInput = (label: string, key: keyof PluginState, min: number, max: number) => {
    const input = h("input", {
      class: "intruder-input narrow",
      type: "number",
      min: String(min),
      max: String(max),
      value: String(state[key]),
      title: label,
    }) as HTMLInputElement;
    input.addEventListener("change", () => {
      (state as any)[key] = Math.max(min, Math.min(Number(input.value) || min, max));
      input.value = String(state[key]);
      saveStateSoon();
    });
    return h("label", { class: "intruder-label" }, `${label}: `, input);
  };

  const controls = h(
    "div",
    { class: "intruder-toolbar" },
    h("label", { class: "intruder-label" }, "Attack mode: ", modeEl),
    numbersInput("Threads", "threads", 1, 64),
    numbersInput("Throttle (ms)", "throttleMs", 0, 60000),
    numbersInput("Max requests", "maxRequests", 1, 1000000),
    numbersInput("Timeout (ms)", "timeoutMs", 1000, 300000),
    h("label", { class: "intruder-label" }, "URL-encode: ", encodeBox),
    h("label", { class: "intruder-label", title: "Save attack requests to HTTP history" }, "Save to history: ", saveBox),
  );

  /* payload sets */
  const setsHint = h("span", { class: "intruder-hint", text: MODE_HINTS[state.mode] });
  setsEl = h("div", { class: "intruder-sets" });
  const resetBtn = h("button", { class: "intruder-button", text: "Reset to template count" });
  resetBtn.addEventListener("click", () => {
    const n = countPositions(state.template);
    state.payloadSets = adjustSets(state.payloadSets, wantedSetCount(state.mode, n));
    refreshSetEditors();
  });
  const setsHeader = h(
    "div",
    { class: "intruder-toolbar" },
    h("strong", { text: "Payload sets" }),
    setsHint,
    resetBtn,
  );

  /* start/stop */
  const startBtn = h("button", { class: "intruder-button primary", text: "▶ Start attack" });
  startBtn.addEventListener("click", () => void startAttack());
  const stopBtn = h("button", { class: "intruder-button", text: "⏹ Stop" });
  stopBtn.addEventListener("click", () => void appSdk?.backend.stopAttack());
  const exportBtn = h("button", { class: "intruder-button", text: "⭳ Export CSV", onclick: exportCsv });
  const clearBtn = h("button", { class: "intruder-button", text: "Clear results", onclick: clearResults });
  statusEl = h("div", { class: "intruder-status", text: "Idle" });

  const runBar = h("div", { class: "intruder-toolbar" }, startBtn, stopBtn, exportBtn, clearBtn, statusEl);

  /* results table */
  const thead = h(
    "thead",
    {},
    h(
      "tr",
      {},
      h("th", { text: "#" }),
      h("th", { text: "Method" }),
      h("th", { text: "Path" }),
      h("th", { text: "Payload" }),
      h("th", { text: "Status" }),
      h("th", { text: "Len" }),
      h("th", { text: "Time" }),
      h("th", { text: "Request ID" }),
      h("th", { text: "Error" }),
    ),
  );
  resultsBodyEl = h("tbody");
  const table = h("table", { class: "intruder-table" }, thead, resultsBodyEl);
  const resultsWrap = h("div", { class: "intruder-results-wrap" }, table);

  root.append(editorHeader, templateEl, posBarEl, controls, setsHeader, setsEl, runBar, resultsWrap);

  refreshPositions();
  refreshSetEditors();
  return root;
}

/* ------------------------- template editor actions ------------------------ */

function markSelection() {
  if (!templateEl) return;
  const s = templateEl.selectionStart ?? 0;
  const e = templateEl.selectionEnd ?? 0;
  if (s === e) return;
  const v = templateEl.value;
  templateEl.value = v.slice(0, s) + "§" + v.slice(s, e) + "§" + v.slice(e);
  templateEl.dispatchEvent(new Event("input"));
}

function clearMarks() {
  if (!templateEl) return;
  templateEl.value = templateEl.value.replaceAll("§", "");
  templateEl.dispatchEvent(new Event("input"));
}

function refreshPositions() {
  if (!posBarEl) return;
  state.template = templateEl?.value ?? state.template;
  const n = countPositions(state.template);
  const labels: string[] = [`Positions: ${n}`];
  for (let i = 0; i < Math.min(n, 20); i++) labels.push(`§${i + 1}§`);
  if (n > 20) labels.push("…");
  posBarEl.textContent = labels.join("  ");
}

/* ------------------------------ payload sets ------------------------------ */

function adjustSets(sets: PayloadSource[], wanted: number): PayloadSource[] {
  const out = sets.slice(0, wanted);
  while (out.length < wanted) out.push({ type: "list", items: [] });
  return out;
}

function refreshSetEditors() {
  if (!setsEl) return;
  const want = wantedSetCount(state.mode, countPositions(state.template));
  state.payloadSets = adjustSets(state.payloadSets, want);
  setsEl.textContent = "";
  state.payloadSets.forEach((set, i) => setsEl!.appendChild(buildSetEditor(i, set)));
}

type ListSource = Extract<PayloadSource, { type: "list" }>;
type NumbersSource = Extract<PayloadSource, { type: "numbers" }>;
type FuzzSource = Extract<PayloadSource, { type: "fuzz" }>;

function buildSetEditor(index: number, set: PayloadSource): HTMLElement {
  const wrap = h("div", { class: "intruder-set" });

  const title = h("div", { class: "intruder-set-title", text: `Set ${index + 1} — ${payloadSummary(set)}` });
  const setTitle = () => {
    title.textContent = `Set ${index + 1} — ${payloadSummary(set)}`;
  };

  const typeSel = h("select", { class: "intruder-input" }) as HTMLSelectElement;
  for (const t of ["list", "numbers", "fuzz"] as const) {
    const o = h("option", { value: t }) as HTMLOptionElement;
    o.textContent = t;
    if (set.type === t) o.selected = true;
    typeSel.appendChild(o);
  }

  const body = h("div", { class: "intruder-set-body" });

  const renderList = (list: ListSource) => {
    const ta = h("textarea", { class: "intruder-set-list", spellcheck: "false" }) as HTMLTextAreaElement;
    ta.value = list.items.join("\n");
    ta.addEventListener("input", () => {
      list.items = ta.value.split("\n");
      setTitle();
      saveStateSoon();
    });
    body.appendChild(ta);
  };

  const renderNumbers = (numbers: NumbersSource) => {
    const mk = (label: string, key: "from" | "to" | "step" | "pad") => {
      const i = h("input", { class: "intruder-input narrow", type: "number", value: String(numbers[key] ?? 0) }) as HTMLInputElement;
      i.addEventListener("change", () => {
        (numbers as any)[key] = Number(i.value) || 0;
        setTitle();
        saveStateSoon();
      });
      return h("label", { class: "intruder-label" }, `${label}: `, i);
    };
    body.append(mk("From", "from"), mk("To", "to"), mk("Step", "step"), mk("Zero-pad (0=off)", "pad"));
  };

  const renderFuzz = (fuzz: FuzzSource) => {
    const charset = h("input", { class: "intruder-input wide", value: fuzz.charset }) as HTMLInputElement;
    const min = h("input", { class: "intruder-input narrow", type: "number", value: String(fuzz.minLength) }) as HTMLInputElement;
    const max = h("input", { class: "intruder-input narrow", type: "number", value: String(fuzz.maxLength) }) as HTMLInputElement;
    const upd = () => {
      fuzz.minLength = Math.max(1, Number(min.value) || 1);
      fuzz.maxLength = Math.max(fuzz.minLength, Number(max.value) || 1);
      setTitle();
      saveStateSoon();
    };
    charset.addEventListener("change", () => {
      fuzz.charset = charset.value;
      setTitle();
      saveStateSoon();
    });
    min.addEventListener("change", upd);
    max.addEventListener("change", upd);
    body.append(
      h("label", { class: "intruder-label" }, "Charset: ", charset),
      h("label", { class: "intruder-label" }, "Min len: ", min),
      h("label", { class: "intruder-label" }, "Max len: ", max),
    );
  };

  const rerender = () => {
    body.textContent = "";
    if (set.type === "list") renderList(set);
    else if (set.type === "numbers") renderNumbers(set);
    else renderFuzz(set);
  };

  typeSel.addEventListener("change", () => {
    const type = typeSel.value as PayloadSource["type"];
    state.payloadSets[index] =
      type === "list"
        ? { type, items: set.type === "list" ? set.items : [] }
        : type === "numbers"
          ? { type, from: 1, to: 100, step: 1 }
          : { type, charset: "abcdef0123456789", minLength: 1, maxLength: 2 };
    // Rebuild the editor against the newly-created source object.
    replaceSetEditor(index);
    setTitle();
    saveStateSoon();
  });

  rerender();
  wrap.append(title, h("div", { class: "intruder-set-toolbar" }, h("label", { class: "intruder-label" }, "Type: ", typeSel)), body);
  return wrap;
}

function replaceSetEditor(index: number) {
  if (!setsEl) return;
  setsEl.textContent = "";
  state.payloadSets.forEach((s, i) => setsEl!.appendChild(buildSetEditor(i, s)));
}

/* --------------------------- start/stop/results --------------------------- */

let totalRequests = 0;
let doneCount = 0;
let resultSeq = 0;

function currentConfig(): AttackConfig {
  return {
    template: (templateEl?.value ?? state.template).replace(/\r?\n/g, "\r\n"),
    mode: state.mode,
    payloads: state.payloadSets,
    encode: state.encode,
    threads: state.threads,
    throttleMs: state.throttleMs,
    maxRequests: state.maxRequests,
    timeoutMs: state.timeoutMs,
    saveRequests: state.saveRequests,
  };
}

async function startAttack() {
  if (!appSdk) return;
  clearResults();
  const res = await appSdk.backend.startAttack(currentConfig());
  if (!res.ok) {
    if (statusEl) statusEl.textContent = `Error: ${res.error ?? "unknown"}`;
    appSdk.log.error(`Intruder: ${res.error}`);
    return;
  }
  shownAttackId = res.attackId ?? "";
  totalRequests = res.totalRequests ?? 0;
  doneCount = 0;
  statusEl?.replaceChildren(
    document.createTextNode(`Starting ${state.mode}: ${totalRequests} requests → ${res.target ?? "?"}`),
  );
}

function onStatus(ev: StatusEvent) {
  if (shownAttackId && ev.attackId !== shownAttackId) return;
  doneCount = ev.done;
  const rate = ev.elapsedMs > 0 ? Math.round((ev.done / ev.elapsedMs) * 1000) : 0;
  const label: Record<StatusEvent["state"], string> = {
    running: "Running",
    completed: "Completed",
    stopped: "Stopped",
    failed: "Failed",
  };
  let text = `${label[ev.state]} — ${ev.done}/${ev.total} (${rate} req/s), ${ev.elapsedMs} ms elapsed`;
  if (ev.error) text += ` — error: ${ev.error}`;
  if (statusEl) statusEl.textContent = text;
}

function addResultRow(ev: ResultEvent) {
  if (shownAttackId && ev.attackId !== shownAttackId) return;
  if (!resultsBodyEl) return;
  resultSeq++;
  if (resultsBodyEl.childElementCount > 5000) resultsBodyEl.firstChild?.remove();

  const status = ev.error ? "ERR" : String(ev.status ?? "?");
  const tr = h(
    "tr",
    { class: `intruder-row s-${status[0]}` },
    h("td", { text: String(ev.seq) }),
    h("td", { text: ev.method }),
    h("td", { class: "mono", text: ev.path }),
    h("td", { class: "mono", text: ev.payloadPreview }),
    h("td", { text: status }),
    h("td", { text: ev.length === undefined ? "—" : String(ev.length) }),
    h("td", { text: ev.timeMs === undefined ? "—" : String(ev.timeMs) }),
    h("td", { text: ev.requestId ?? "—" }),
    h("td", { class: "err", text: ev.error ?? "" }),
  );
  resultsBodyEl.appendChild(tr);
  resultsCsvRows.push(
    [
      ev.seq,
      ev.index,
      ev.method,
      ev.path,
      JSON.stringify(ev.payload),
      status,
      ev.length ?? "",
      ev.timeMs ?? "",
      ev.requestId ?? "",
      ev.error ?? "",
    ]
      .map(csvEscape)
      .join(","),
  );
}

function csvEscape(v: unknown): string {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

function clearResults() {
  resultsCsvRows = [];
  resultSeq = 0;
  if (resultsBodyEl) resultsBodyEl.textContent = "";
  if (statusEl) statusEl.textContent = "Idle";
}

function exportCsv() {
  const header = "seq,index,method,path,payloads,status,length,time_ms,request_id,error";
  const blob = new Blob([header + "\n" + resultsCsvRows.join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "intruder-results.csv";
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* --------------------------------- misc ---------------------------------- */

async function loadRequestId(id: string) {
  if (!appSdk) return;
  const trimmed = id.trim();
  if (!trimmed) return;
  const raw = await appSdk.backend.getRawRequest(trimmed);
  if (!raw) {
    appSdk.log.error(`Intruder: request ${trimmed} not found`);
    return;
  }
  state.template = raw;
  if (templateEl) {
    templateEl.value = raw;
    templateEl.dispatchEvent(new Event("input"));
  }
}

function applySample(name: string) {
  const sample = SAMPLES.find((s) => s.name === name);
  if (!sample || !templateEl) return;
  templateEl.value = sample.template;
  state.template = sample.template;
  state.payloadSets = adjustSets([sample.payload], wantedSetCount(state.mode, countPositions(sample.template)));
  templateEl.dispatchEvent(new Event("input"));
  refreshSetEditors();
}

function syncTemplateEditor() {
  if (templateEl) {
    templateEl.value = state.template;
    templateEl.dispatchEvent(new Event("input"));
  }
}

/* ---------------------------------- CSS ----------------------------------- */

const CSS = `
.intruder-root { display: flex; flex-direction: column; height: 100%; width: 100%; padding: 12px; gap: 8px; box-sizing: border-box; background: var(--bg-primary, #16191f); color: var(--text-bright, #e2e8f0); font-family: ui-sans-serif, system-ui, sans-serif; overflow: auto; }
.intruder-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.intruder-hint { color: var(--text-muted, #8b95a5); font-size: 12px; }
.intruder-button { background: var(--bg-surface, #20242d); color: var(--text-bright, #e2e8f0); border: 1px solid var(--bg-bright, #404653); border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 12px; }
.intruder-button:hover { border-color: var(--accent, #3aa9ff); }
.intruder-button.primary { background: #1e5f8d; border-color: #3aa9ff; }
.intruder-input { background: var(--bg-surface, #20242d); color: var(--text-bright, #e2e8f0); border: 1px solid var(--bg-bright, #404653); border-radius: 6px; padding: 3px 6px; font-size: 12px; }
.intruder-input.narrow { width: 72px; }
.intruder-input.wide { width: 260px; }
.intruder-label { font-size: 12px; color: var(--text-muted, #8b95a5); display: inline-flex; align-items: center; gap: 4px; }
.intruder-template { width: 100%; min-height: 180px; resize: vertical; background: var(--bg-surface, #20242d); color: var(--text-bright, #e2e8f0); border: 1px solid var(--bg-bright, #404653); border-radius: 6px; padding: 8px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.45; box-sizing: border-box; }
.intruder-sets { display: flex; gap: 12px; flex-wrap: wrap; }
.intruder-set { flex: 1 1 280px; border: 1px solid var(--bg-bright, #404653); border-radius: 8px; padding: 8px; display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.intruder-set-title { font-size: 12px; font-weight: 600; }
.intruder-set-list { width: 100%; height: 110px; resize: vertical; background: var(--bg-surface, #20242d); color: var(--text-bright, #e2e8f0); border: 1px solid var(--bg-bright, #404653); border-radius: 6px; padding: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; box-sizing: border-box; }
.intruder-status { margin-left: auto; font-size: 12px; color: var(--text-muted, #8b95a5); }
.intruder-results-wrap { flex: 1; overflow: auto; border: 1px solid var(--bg-bright, #404653); border-radius: 8px; min-height: 160px; }
.intruder-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.intruder-table th { position: sticky; top: 0; background: var(--bg-surface, #20242d); text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--bg-bright, #404653); }
.intruder-table td { padding: 3px 8px; border-bottom: 1px solid rgba(64, 70, 83, 0.4); white-space: nowrap; max-width: 480px; overflow: hidden; text-overflow: ellipsis; }
.intruder-table td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.intruder-table td.err { color: #ff7b72; }
.intruder-row.s-2 td:nth-child(5) { color: #56d364; }
.intruder-row.s-3 td:nth-child(5) { color: #d29922; }
.intruder-row.s-4 td:nth-child(5), .intruder-row.s-5 td:nth-child(5) { color: #ff7b72; }
`;
