import {
  composeRequest,
  generateTuples,
  materializePayloads,
  normalizeRawHttp,
  parseRawRequest,
  splitTemplate,
} from "../src/backend/engine";

let failures = 0;
function eq(name: string, got: unknown, want: unknown) {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) {
    failures++;
    console.error(`FAIL ${name}\n  got:  ${g}\n  want: ${w}`);
  } else {
    console.log(`ok   ${name}`);
  }
}

/* splitTemplate */
eq("split single", (() => { const s = splitTemplate("a§x§b"); return { parts: s.parts, n: s.positionCount }; })(),
  { parts: ["a", "x", "b"], n: 1 });
eq("split two", (() => { const s = splitTemplate("a§x§b§y§c"); return { parts: s.parts, n: s.positionCount }; })(),
  { parts: ["a", "x", "b", "y", "c"], n: 2 });
eq("split trailing marker", splitTemplate("a§x§").positionCount, 1);
eq("split none", splitTemplate("no markers").positionCount, 0);

/* materializePayloads */
eq("numbers simple", materializePayloads({ type: "numbers", from: 1, to: 5, step: 2 }), ["1", "3", "5"]);
eq("numbers pad", materializePayloads({ type: "numbers", from: 7, to: 9, step: 1, pad: 4 }), ["0007", "0008", "0009"]);
eq("numbers bad range errors", typeof materializePayloads({ type: "numbers", from: 5, to: 1, step: 1 }) === "string", true);
eq(
  "numbers bad range is string",
  typeof materializePayloads({ type: "numbers", from: 5, to: 1, step: 1 }) === "string",
  true,
);
eq("fuzz len1", materializePayloads({ type: "fuzz", charset: "ab", minLength: 1, maxLength: 1 }), ["a", "b"]);
eq("fuzz len2", materializePayloads({ type: "fuzz", charset: "ab", minLength: 1, maxLength: 2 }),
  ["a", "b", "aa", "ab", "ba", "bb"]);
eq("fuzz empty charset", typeof materializePayloads({ type: "fuzz", charset: "", minLength: 1, maxLength: 1 }), "string");

/* generateTuples */
const A = ["a1", "a2"];
const B = ["b1", "b2"];
eq("sniper (2 pos, set of 2)", generateTuples("sniper", [A], 2),
  [["a1", ""], ["a2", ""], ["", "a1"], ["", "a2"]]);
eq("battering-ram", generateTuples("battering-ram", [A], 2),
  [["a1", "a1"], ["a2", "a2"]]);
eq("pitchfork", generateTuples("pitchfork", [A, B], 2),
  [["a1", "b1"], ["a2", "b2"]]);
eq("pitchfork shortest wins", generateTuples("pitchfork", [["x"], B], 2), [["x", "b1"]]);
// Odometer order: the LAST position varies fastest.
eq("cluster-bomb", generateTuples("cluster-bomb", [A, B], 2),
  [["a1", "b1"], ["a1", "b2"], ["a2", "b1"], ["a2", "b2"]]);
eq("cluster-bomb 3 lists", generateTuples("cluster-bomb", [["p", "q"], ["x"], ["1", "2"]], 3),
  [["p", "x", "1"], ["p", "x", "2"], ["q", "x", "1"], ["q", "x", "2"]]);
eq(
  "cluster-bomb mismatch is string",
  typeof generateTuples("cluster-bomb", [A], 2) === "string",
  true,
);
eq("empty set errors", typeof generateTuples("sniper", [[]], 1) === "string", true);

/* composeRequest */
eq("compose single", composeRequest(["GET /", "x", " HTTP/1.1"], ["val"], false), "GET /val HTTP/1.1");
eq("compose empty marker", composeRequest(["GET /", "", "/ HTTP/1.1"], ["q"], false), "GET /q/ HTTP/1.1");
eq("compose encode", composeRequest(["GET /?q=", "v", ""], ["a b"], true), "GET /?q=a%20b");

/* parseRawRequest */
const raw = "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
const p = parseRawRequest(raw);
eq("parse method", p.method, "POST");
eq("parse path", p.path, "/login");
eq("parse host", p.host, "example.com");
eq("parse body", p.body, '{"a":1}');
eq("parse absolute", parseRawRequest("GET https://foo.com:8443/p?q=1 HTTP/1.1\r\n\r\n").host, "foo.com:8443");
const p2 = parseRawRequest("GET https://foo.com/x HTTP/1.1\r\nHost: ignored.example\r\n\r\n");
eq("absolute overrides host", p2.host, "foo.com");
eq("absolute path", p2.path, "/x");

/* normalizeRawHttp */
eq("normalize lf-only", normalizeRawHttp("GET / HTTP/1.1\nHost: x\n\n"), "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
eq("normalize keep CRLF", normalizeRawHttp("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), "GET / HTTP/1.1\r\nHost: x\r\n\r\n");

/* full end-to-end composition: 2 markers + replace */
const tpl = "GET /api/users/§ID§?x=§Q§ HTTP/1.1\r\nHost: h\r\n\r\n";
const parts = splitTemplate(tpl).parts;
eq("e2e build", normalizeRawHttp(composeRequest(parts, ["123", "1%20"], false)),
  "GET /api/users/123?x=1%20 HTTP/1.1\r\nHost: h\r\n\r\n");

if (failures > 0) {
  console.error(`\n${failures} failing`);
  process.exit(1);
} else {
  console.log("\nAll engine tests passed");
}
