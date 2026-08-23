/* Rendering for extraction results.
 *
 * SECURITY: every value here originates from a language model whose input is an
 * arbitrary clinical note, so a prompt injection can place executable markup in
 * any string field. Everything interpolated into markup MUST go through esc().
 * scripts/check-xss.js exercises this module against real payloads — run it
 * after any change to this file.
 *
 * STYLING: the classes emitted here are defined in styles/results.css, a plain
 * imported stylesheet rather than a component <style> block. Astro scopes
 * component styles to elements present at build time; everything below is built
 * at runtime and would not match a scoped selector.
 */
import { esc } from "./api.js";

/* Bands match the definitions the system prompt gives the model:
 *   0.90-1.00  exact and fully documented — safe to bill
 *   0.75-0.89  correct, but documentation has minor gaps
 *   below 0.75 never reaches here; the parser moves it to suggested_codes
 * Splitting at 0.8 (the previous behaviour) put almost every confirmed code in
 * the top band, which made the indicator carry no information. */
const confidenceTier = (confidence) =>
  confidence >= 0.9 ? "high" : confidence >= 0.75 ? "med" : "low";

/** Group a code system into one of the three families the badge colours. */
function systemFamily(codeType) {
  const label = String(codeType || "").toUpperCase();
  if (label.startsWith("ICD")) return "icd";
  if (label.startsWith("CPT")) return "cpt";
  if (label.startsWith("HCPCS")) return "hcpcs";
  return "other";
}

const shortSystem = (codeType, fallback) => {
  const label = String(codeType || fallback || "").toUpperCase();
  // "ICD-10-CM" is too long for a pill; the family is what matters at a glance.
  if (label.startsWith("ICD-10-PCS")) return "ICD-10-PCS";
  if (label.startsWith("ICD")) return "ICD-10";
  return label || "CODE";
};

const DOC_TIERS = { strong: "strong", moderate: "moderate", weak: "weak" };

/** One code bubble plus its tooltip. */
function bubble(item, index) {
  const confidence = parseFloat(item.confidence) || 0;
  const percent = Math.round(confidence * 100);
  const tier = confidenceTier(confidence);
  const family = systemFamily(item.code_type);
  const tipId = `code-tip-${index}`;

  const docStrength = String(item.documentation_strength || "").toLowerCase();
  const docTier = DOC_TIERS[docStrength];

  const pills = [
    item.billing_priority
      ? `<span class="tip__pill">${esc(item.billing_priority)}</span>`
      : "",
    docStrength
      ? `<span class="tip__pill${docTier ? ` tip__pill--${docTier}` : ""}">${esc(docStrength)} documentation</span>`
      : "",
    `<span class="tip__pill">${percent}% confidence</span>`,
  ]
    .filter(Boolean)
    .join("");

  const reasoning = item.reasoning
    ? `<span class="tip__label">Supporting documentation</span>
       <div class="tip__reason">${esc(item.reasoning)}</div>`
    : "";

  return `
    <div class="codechip-wrap">
      <button
        type="button"
        class="codechip codechip--${tier}"
        style="--conf:${percent}"
        aria-describedby="${tipId}"
      >
        <span class="codechip__system" data-system="${family}">${esc(shortSystem(item.code_type, item.type))}</span>
        <span class="codechip__code">${esc(item.code)}</span>
        <span class="codechip__conf" aria-hidden="true"></span>
      </button>
      <div class="tip" id="${tipId}" role="tooltip">
        <div class="tip__desc">${esc(item.description || "No description provided")}</div>
        ${reasoning}
        <div class="tip__meta">${pills}</div>
      </div>
    </div>`;
}

/** One suggested-code chip plus its tooltip.
 *
 * Suggested codes carry no confidence or documentation strength — the model
 * placed them here precisely because that evidence is missing. The chip is
 * styled as an open question rather than a value, and the tooltip leads with
 * what documentation would settle it, which is the actionable part.
 */
function suggestedChip(item, index) {
  const family = systemFamily(item.code_type);
  const tipId = `sug-tip-${index}`;

  const why = item.reason_suggested
    ? `<span class="tip__label">Why suggested</span>
       <div class="tip__reason">${esc(item.reason_suggested)}</div>`
    : "";

  const needed = item.documentation_needed
    ? `<div class="tip__needed">
         <span class="tip__label tip__label--warn">Documentation needed</span>
         ${esc(item.documentation_needed)}
       </div>`
    : "";

  return `
    <div class="codechip-wrap">
      <button
        type="button"
        class="codechip codechip--suggested"
        aria-describedby="${tipId}"
      >
        <span class="codechip__system" data-system="${family}">${esc(shortSystem(item.code_type, item.type))}</span>
        <span class="codechip__code">${esc(item.code)}</span>
        <span class="codechip__query" aria-hidden="true">?</span>
      </button>
      <div class="tip" id="${tipId}" role="tooltip">
        <div class="tip__desc">${esc(item.description || "No description provided")}</div>
        ${why}
        ${needed}
      </div>
    </div>`;
}


/** The full table, available behind a toggle for line-by-line review. */
function detailTable(confirmed) {
  const rows = confirmed
    .map((item) => {
      const percent = Math.round((parseFloat(item.confidence) || 0) * 100);
      return `<tr>
        <td class="td-code">${esc(item.code)}</td>
        <td>${esc(shortSystem(item.code_type, item.type))}</td>
        <td>${esc(item.description || "—")}</td>
        <td class="td-reasoning">${esc(item.reasoning || "—")}</td>
        <td>${esc(item.documentation_strength || "—")}</td>
        <td>${percent}%</td>
      </tr>`;
    })
    .join("");

  return `
    <button type="button" class="detail-toggle" id="detailToggle" aria-expanded="false"
            aria-controls="detailTable">Show full detail</button>
    <div class="detail-table" id="detailTable" hidden>
      <table>
        <caption class="visually-hidden">Billable codes extracted from the clinical note</caption>
        <thead>
          <tr>
            <th scope="col">Code</th>
            <th scope="col">System</th>
            <th scope="col">Description</th>
            <th scope="col">Clinical reasoning</th>
            <th scope="col">Documentation</th>
            <th scope="col">Confidence</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

export function formatResults(data) {
  const confirmed = Array.isArray(data.confirmed_codes) ? data.confirmed_codes : [];
  const suggested = Array.isArray(data.suggested_codes) ? data.suggested_codes : [];

  if (!confirmed.length && !suggested.length) {
    return '<div class="error-box">⚠️ No codes were found in this note.</div>';
  }

  let html = "";

  if (confirmed.length) {
    html += `
      <div class="results-header">
        <span class="results-title">Confirmed codes</span>
        <span class="results-meta">${confirmed.length} ready to bill · hover for reasoning</span>
      </div>
      <div class="codechips">${confirmed.map(bubble).join("")}</div>
      ${detailTable(confirmed)}`;
  }

  if (suggested.length) {
    html += `
      <div class="suggested-section">
        <div class="results-header">
          <span class="results-title">Suggested codes</span>
          <span class="results-meta">
            ${suggested.length} need${suggested.length === 1 ? "s" : ""} clarification
            &middot; hover for what is missing
          </span>
        </div>
        <p class="suggested-note">
          Require physician confirmation or more documentation before billing.
        </p>
        <div class="codechips">${suggested.map(suggestedChip).join("")}</div>
      </div>`;
  }

  return html;
}

/**
 * Wire up tooltip behaviour after results are inserted.
 *
 * Hover and keyboard focus are handled in CSS. This adds what CSS cannot: a
 * tap-to-open path for touch devices, and an edge check so a tooltip near the
 * container boundary does not overflow off screen.
 */
export function initResultInteractions(container) {
  const toggle = container.querySelector("#detailToggle");
  const table = container.querySelector("#detailTable");
  if (toggle && table) {
    toggle.addEventListener("click", () => {
      const open = table.hasAttribute("hidden");
      table.toggleAttribute("hidden", !open);
      toggle.setAttribute("aria-expanded", String(open));
      toggle.textContent = open ? "Hide full detail" : "Show full detail";
    });
  }

  const wraps = [...container.querySelectorAll(".codechip-wrap")];

  // Flip the anchor when a tooltip would spill past the container edge.
  const positionTips = () => {
    const bounds = container.getBoundingClientRect();
    for (const wrap of wraps) {
      wrap.classList.remove("tip-left", "tip-right");
      const tip = wrap.querySelector(".tip");
      if (!tip) continue;
      const width = tip.offsetWidth;
      const centre = wrap.getBoundingClientRect().left + wrap.offsetWidth / 2;
      if (centre - width / 2 < bounds.left) wrap.classList.add("tip-left");
      else if (centre + width / 2 > bounds.right) wrap.classList.add("tip-right");
    }
  };
  positionTips();
  window.addEventListener("resize", positionTips, { passive: true });

  // Touch has no hover, so tapping a bubble pins its tooltip.
  for (const wrap of wraps) {
    wrap.querySelector(".codechip")?.addEventListener("click", (event) => {
      event.stopPropagation();
      const wasOpen = wrap.classList.contains("is-open");
      for (const other of wraps) other.classList.remove("is-open");
      wrap.classList.toggle("is-open", !wasOpen);
    });
  }
  document.addEventListener("click", () => {
    for (const wrap of wraps) wrap.classList.remove("is-open");
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      for (const wrap of wraps) wrap.classList.remove("is-open");
    }
  });
}

/** Fallback view when the parser could not produce a structured result. */
export const formatRaw = (result) =>
  `<pre class="raw-result">${esc(JSON.stringify(result, null, 2))}</pre>`;

/** Error view. The message may carry server text, so it is escaped too. */
export const formatError = (message) => `<div class="error-box">❌ ${esc(message)}</div>`;
