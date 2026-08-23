/* Speech-to-text for the clinical note field.
 *
 * Uses the browser's SpeechRecognition API where available; the control hides
 * itself entirely where it is not, rather than presenting a button that does
 * nothing.
 */
const SpeechRecognition =
  typeof window !== "undefined" &&
  (window.SpeechRecognition || window.webkitSpeechRecognition);

export const isSupported = () => Boolean(SpeechRecognition);

export function createDictation({ textarea, button, onTranscript, onStart }) {
  if (!SpeechRecognition) {
    if (button) button.style.display = "none";
    return null;
  }

  const recognition = new SpeechRecognition();
  recognition.continuous = true;
  recognition.interimResults = true;
  recognition.lang = "en-US";

  let listening = false;

  const setButtonState = () => {
    if (!button) return;
    button.textContent = listening ? "🔴 Stop Dictation" : "🎤 Dictate";
    button.classList.toggle("listening", listening);
    button.setAttribute("aria-pressed", String(listening));
    textarea.classList.toggle("listening", listening);
    textarea.placeholder = listening
      ? "Listening… speak your clinical note."
      : "e.g. Patient presents with Type 2 diabetes mellitus with diabetic nephropathy…";
  };

  recognition.onresult = (event) => {
    let finalText = "";
    for (let i = event.resultIndex; i < event.results.length; i++) {
      if (event.results[i].isFinal) finalText += event.results[i][0].transcript;
    }
    if (finalText.trim()) {
      const separator = textarea.value && !textarea.value.endsWith(" ") ? " " : "";
      textarea.value += separator + finalText.trim();
      onTranscript?.();
    }
  };

  recognition.onerror = (event) => {
    if (event.error === "not-allowed") {
      window.alert("Microphone access denied. Allow microphone access and try again.");
    }
    listening = false;
    setButtonState();
  };

  // Recognition auto-stops after silence; restart while still toggled on.
  recognition.onend = () => {
    if (listening) recognition.start();
  };

  const stop = () => {
    if (!listening) return;
    listening = false;
    recognition.stop();
    setButtonState();
  };

  const toggle = () => {
    listening = !listening;
    if (listening) {
      recognition.start();
      onStart?.();
    } else {
      recognition.stop();
    }
    setButtonState();
  };

  button?.addEventListener("click", toggle);
  setButtonState();

  return { toggle, stop, isListening: () => listening };
}
