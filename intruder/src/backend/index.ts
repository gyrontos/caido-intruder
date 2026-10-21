import { RequestSpec } from "caido:utils";
import type { SDK } from "caido:plugin";
import type { API, Events } from "../shared/api";
import type { AttackConfig, AttackStartResult, ResultEvent, StatusEvent } from "../shared/types";
import {
  composeRequest,
  generateTuples,
  materializePayloads,
  normalizeRawHttp,
  parseRawRequest,
  splitTemplate,
} from "./engine";

type IntruderSDK = SDK<API, Events>;

interface RunState {
  attackId: string;
  config: AttackConfig;
  parts: string[];
  running: boolean;
  stopRequested: boolean;
  done: number;
  total: number;
  startedAt: number;
}

/** Only one attack runs at a time (one global tab, like Intruder's single tab). */
let current: RunState | null = null;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function init(sdk: IntruderSDK) {
  sdk.api.register("startAttack", (sdk, config: AttackConfig): Promise<AttackStartResult> => {
    return startAttack(sdk, config);
  });

  sdk.api.register("stopAttack", async () => {
    if (!current || !current.running) return false;
    current.stopRequested = true;
    return true;
  });

  sdk.api.register("getRawRequest", async (sdk, requestId: string) => {
    try {
      const rr = await sdk.requests.get(requestId);
      return rr?.request?.getRaw()?.toText();
    } catch (e) {
      sdk.console.error(`Intruder getRawRequest failed: ${String(e)}`);
      return undefined;
    }
  });
}

async function startAttack(sdk: IntruderSDK, config: AttackConfig): Promise<AttackStartResult> {
  if (current && current.running) {
    return { ok: false, error: "An attack is already running — stop it first." };
  }
  if (!config || !config.template) return { ok: false, error: "Template is empty" };

  const { parts, positionCount } = splitTemplate(config.template);
  if (positionCount === 0) {
    return { ok: false, error: "No §positions§ marked in the template. Select text and click Mark, or type §markers§ directly." };
  }

  const lists: string[][] = [];
  for (const src of config.payloads) {
    const expanded = materializePayloads(src);
    if (typeof expanded === "string") return { ok: false, error: expanded };
    lists.push(expanded);
  }

  const mode = config.mode ?? "sniper";
  const generated = generateTuples(mode, lists, positionCount);
  if (typeof generated === "string") return { ok: false, error: generated };
  let tuples = generated;

  const cap = Math.max(1, config.maxRequests ?? 10000);
  let truncated = false;
  if (tuples.length > cap) {
    tuples = tuples.slice(0, cap);
    truncated = true;
  }

  // Validate the template parses as a request and knows its target.
  const probe = parseRawRequest(composeRequest(parts, new Array(positionCount).fill(""), false));
  if (!probe.host) {
    return { ok: false, error: "No Host header (or absolute-form request line) found — cannot determine the target." };
  }

  const attackId = `${Date.now().toString(36)}`;

  current = {
    attackId,
    config,
    parts,
    running: true,
    stopRequested: false,
    done: 0,
    total: tuples.length,
    startedAt: Date.now(),
  };

  sdk.console.log(
    `Intruder: starting ${mode} attack with ${tuples.length} requests` +
      (truncated ? ` (truncated by max requests cap of ${cap})` : ""),
  );

  // Fire-and-forget so the RPC returns immediately; progress streams via events.
  runAttack(sdk, current, tuples).catch((e) => {
    sdk.console.error(`Intruder: attack crashed: ${String(e)}`);
    if (current) {
      current.running = false;
      emitStatus(sdk, current, "failed", String((e as Error | undefined)?.message ?? e));
    }
  });

  return {
    ok: true,
    attackId,
    totalRequests: tuples.length,
    positionCount,
    firstLine: probe.method + " " + probe.path,
    target: probe.host,
  };
}

async function runAttack(sdk: IntruderSDK, state: RunState, tuples: string[][]) {
  const save = state.config.saveRequests ?? false;
  const threads = Math.max(1, Math.min(64, state.config.threads ?? 4));
  const throttleMs = Math.max(0, state.config.throttleMs ?? 0);
  const timeout = Math.max(1000, state.config.timeoutMs ?? 10000);

  emitStatus(sdk, state, "running");

  let next = 0;
  let seq = 0;

  const dispatchOne = async (): Promise<boolean> => {
    if (state.stopRequested || !state.running || next >= tuples.length) return false;
    const index = next++;
    const values = tuples[index];
    const rawHttp = normalizeRawHttp(composeRequest(state.parts, values, state.config.encode ?? false));

    const parsed = parseRawRequest(rawHttp);
    let ev: ResultEvent = {
      kind: "result",
      attackId: state.attackId,
      seq: ++seq,
      index,
      payload: values,
      payloadPreview:
        values.filter((v) => v !== "").join("  |  ") || "(empty)",
      method: parsed.method,
      host: parsed.host,
      path: parsed.path,
    };

    if (!parsed.host) {
      ev.error = "Request does not parse: missing Host";
      state.done++;
      sdk.api.send("intruder:result", ev);
      return true;
    }

    const t0 = Date.now();
    try {
      const spec = RequestSpec.parse(rawHttp as unknown as Parameters<typeof RequestSpec.parse>[0]);
      const { request, response } = await sdk.requests.send(spec, {
        save,
        timeouts: { global: timeout },
      });
      ev = {
        ...ev,
        status: response?.getCode(),
        length: response?.getBody()?.length,
        timeMs: response ? response.getRoundtripTime() : Date.now() - t0,
        requestId: save ? request.getId() : undefined,
        firstLine: `HTTP/1.1 ${response?.getCode() ?? "?"}`,
      };
    } catch (e) {
      const msg = String((e as Error | undefined)?.message ?? e);
      ev = { ...ev, error: msg.slice(0, 200), timeMs: Date.now() - t0 };
    }
    state.done++;
    sdk.api.send("intruder:result", ev);
    return true;
  };

  const worker = async () => {
    // The throttle spaces out dispatches globally, at most one send starts per tick.
    while (state.running && !state.stopRequested) {
      if (throttleMs > 0 && next > 0) await sleep(throttleMs);
      const dispatched = await dispatchOne();
      if (!dispatched) return;
    }
  };

  const workers = Array.from({ length: threads }, () => worker());
  try {
    await Promise.all(workers);
  } finally {
    state.running = false;
  }
  emitStatus(sdk, state, state.stopRequested ? "stopped" : "completed");
}

function emitStatus(
  sdk: IntruderSDK,
  state: RunState,
  stateName: StatusEvent["state"],
  error?: string,
) {
  const ev: StatusEvent = {
    kind: "status",
    attackId: state.attackId,
    state: stateName,
    error,
    done: state.done,
    total: state.total,
    elapsedMs: Date.now() - state.startedAt,
  };
  sdk.api.send("intruder:status", ev);
}
