/* Helpers shared by the auth forms.
 *
 * The alert renderer and the JSON-with-fallback parser were reimplemented in
 * each of the five auth pages, with slightly different wording per copy.
 */

/** Show a message in the page's alert region. */
export function showAlert(message, type = "error") {
  const box = document.querySelector("#alert");
  if (!box) return;
  box.textContent = message;
  box.className = `alert show ${type}`;
}

/** Clear the alert region. */
export function clearAlert() {
  const box = document.querySelector("#alert");
  if (box) box.className = "alert";
}

/** Parse a response body as JSON, falling back to a readable message. */
export async function payload(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return {
      detail: response.ok
        ? "Unexpected server response."
        : "The server could not complete the request. Please try again.",
    };
  }
}

/** Wire a form submit handler with disable-while-pending and error display. */
export function onSubmit(selector, handler, { button = "#submit" } = {}) {
  const form = document.querySelector(selector);
  const submitButton = document.querySelector(button);
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearAlert();
    if (submitButton) submitButton.disabled = true;
    try {
      await handler(form);
    } catch (error) {
      showAlert(error.message);
    } finally {
      if (submitButton) submitButton.disabled = false;
    }
  });
}

/** The token from a one-time link in the query string. */
export const linkToken = () =>
  new URLSearchParams(window.location.search).get("token") || "";
