import type { AttackConfig, AttackStartResult, ResultEvent, StatusEvent } from "./types";

/** Simple DefineAPI compatible with both the older and current Caido SDK typings. */
export type DefineAPI<T = {}> = T;

/** Backend RPC methods callable from the frontend via sdk.backend.*. */
export type API = DefineAPI<{
  startAttack: (config: AttackConfig) => Promise<AttackStartResult>;
  stopAttack: () => Promise<boolean>;
  /** Fetch the raw HTTP request text of a saved request by id. */
  getRawRequest: (requestId: string) => Promise<string | undefined>;
}>;

/** Backend events streamed to the frontend via sdk.backend.onEvent. */
export type Events = {
  "intruder:result": (ev: ResultEvent) => void;
  "intruder:status": (ev: StatusEvent) => void;
};
