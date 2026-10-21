/**
 * Shared types between the Intruder frontend and backend.
 * This file is bundled into both scripts separately (no runtime imports across bundles).
 */

export type PayloadSource =
  | { type: "list"; items: string[] }
  | { type: "numbers"; from: number; to: number; step: number; pad?: number }
  | { type: "fuzz"; charset: string; minLength: number; maxLength: number };

export type AttackMode = "sniper" | "battering-ram" | "pitchfork" | "cluster-bomb";

export interface AttackConfig {
  /** Raw HTTP request template with §position§ markers. */
  template: string;
  mode: AttackMode;
  /**
   * Payload sources. For sniper/battering-ram a single source is used.
   * For pitchfork/cluster-bomb, one source per marked position.
   */
  payloads: PayloadSource[];
  /** URL-encode the injected insertion values. */
  encode?: boolean;
  /** Concurrent requests. Default 4, capped at 64. */
  threads?: number;
  /** Global throttle between dispatches in ms. Default 0. */
  throttleMs?: number;
  /** Hard cap on generated requests. Default 10000. */
  maxRequests?: number;
  /** Save the attack requests/responses into Caido's database (visible in history). Default false. */
  saveRequests?: boolean;
  /** Global per-request timeout in ms. Default 10000. */
  timeoutMs?: number;
}

export interface AttackStartResult {
  ok: boolean;
  error?: string;
  /** Unique id for this run, echoed by every event. */
  attackId?: string;
  /** Number of request/payload combinations queued. */
  totalRequests?: number;
  /** Number of marked positions. */
  positionCount?: number;
  /** Human-readable target summary. */
  target?: string;
  /** The request line of the template (for display). */
  firstLine?: string;
}

export interface ResultEvent {
  kind: "result";
  attackId: string;
  /** 1-based sequence number within the attack. */
  seq: number;
  /** Combination index (dispatch order). */
  index: number;
  payload: string[];
  /** Compact preview for the grid. */
  payloadPreview: string;
  method: string;
  host: string;
  path: string;
  status?: number;
  /** Response length in bytes, if known. */
  length?: number;
  /** Round-trip milliseconds reported by Caido, when known. */
  timeMs?: number;
  /** Caido request id (valid only when saveRequests is true). */
  requestId?: string;
  error?: string;
  firstLine?: string;
}

export interface StatusEvent {
  kind: "status";
  attackId: string;
  state: "running" | "completed" | "stopped" | "failed";
  error?: string;
  done: number;
  total: number;
  elapsedMs: number;
}
