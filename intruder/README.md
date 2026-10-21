# Intruder for Caido

A Burp **Intruder**-style attack tool as a Caido plugin.

- **Payload positions** marked with `§...§` in a raw request template
- **Attack modes**: Sniper, Battering Ram, Pitchfork, Cluster Bomb
- **Payload sets**: literal lists, number ranges (optionally padded), brute-force charset fuzzing
- **URL-encode payload option**, thread pool + throttle, safety request cap
- **Results table** (status, length, time, payload, positions) with click-through to the saved request in Caido's HTTP history
- Templates persist across sessions via frontend storage; "Send to Intruder" from any request in HTTP history

## Files

```
intruder/
  manifest.json            # Caido plugin package manifest
  src/backend/index.ts     # Attack engine (runs on Caido's JS backend runtime)
  src/frontend/index.ts    # UI (custom page + command palette integration)
  build.ts                 # esbuild bundler + zip packager
  dist/plugin_package.zip  # produced by: bun run build (or npm run build)
```

## Building

```bash
npm ci      # lockfile-exact install (npm install works too)
npm test    # engine unit tests (attack modes, parsers, payload generators)
npm run build
```

Produces `dist/plugin_package.zip` (ESM `frontend/script.js` + `backend/script.js`, each exporting `init`, per the current Caido plugin package format).

## Installing

In Caido: **Settings → Plugins → Install from file** and select `dist/plugin_package.zip`.
Then open the **Intruder** page in the sidebar, or right-click/click a request in HTTP
history and run the **Send to Intruder** command from the command palette.

## Marking positions

Select text and click **§ Mark §** to wrap it in §markers§, or write them directly.
`Clear marks` strips all `§` characters. Each marked region becomes a position in order of appearance.

## Attack modes

| Mode | Behaviour |
| --- | --- |
| Sniper | One payload set; each position is attacked in turn with every payload |
| Battering ram | One payload set; every position is replaced with the *same* payload at each step |
| Pitchfork | One payload list per position; lists are paired by index (parallel iteration) |
| Cluster bomb | One payload list per position; Cartesian product over all lists |

Requests are sent through Caido (`sdk.requests.send`) so they honor Caido's proxy settings and
appear (optionally saved) in the project. Responses are not automatically saved to history
(`save: false`) to keep attacks fast; each result row links via the in-flight request ID.
