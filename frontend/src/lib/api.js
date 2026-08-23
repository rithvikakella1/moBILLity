/* Shared browser helpers.
 *
 * esc(), the cookie reader, and the fetch wrapper were previously duplicated
 * across app.html, workflows.html, admin.html, and privacy.html — with small
 * differences between copies. One definition now.
 */

/** Escape a value destined for innerHTML.
 *
 * Extraction results come from a language model whose input is an arbitrary
 * clinical note, so a prompt injection can place executable markup in any
 * string field. Everything interpolated into markup goes through this.
 */
export const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );

/** Read a cookie by name, URL-decoded. */
export const cookie = (name) =>
  decodeURIComponent(
    document.cookie
      .split("; ")
      .find((row) => row.startsWith(name + "="))
      ?.split("=")[1] || "",
  );

/** The CSRF token the server expects echoed back on authenticated writes. */
export const csrfToken = () => cookie("mobillity_csrf");

/** Fetch wrapper that attaches CSRF, parses errors, and redirects on 401. */
export async function api(path, options = {}) {
  options.headers = { ...(options.headers || {}), "X-CSRF-Token": csrfToken() };
  if (options.body) options.headers["Content-Type"] = "application/json";

  const response = await fetch(path, options);
  if (response.status === 401) {
    window.location.href = "/login";
    throw new Error("Sign in required");
  }
  if (response.status === 204) return null;

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(
      response.ok
        ? "Unexpected server response."
        : "The server could not complete the request. Please try again.",
    );
  }
  if (!response.ok) throw new Error(data.detail || "Request failed");
  return data;
}

/** Sign out and return to the login page. */
export async function logout() {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  window.location.href = "/login";
}

/** Record an allowlisted analytics event. Failures are deliberately silent. */
export function track(eventName, page = "app") {
  fetch("/api/analytics/events", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: JSON.stringify({ event_name: eventName, page }),
  }).catch(() => {});
}

/** Format an ISO timestamp for display in the viewer's locale. */
export const when = (value) =>
  new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
