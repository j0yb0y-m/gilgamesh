/* Gilgamesh's own client glue. Deliberately tiny.
 *
 * The SSE extension for htmx (`htmx-ext-sse`) is not used: its licence is undeclared in
 * the npm metadata and no licence file was detected, which fails constraint C1 (open
 * source only). FastAPI serves SSE natively, so the browser side is ~15 lines.
 */
(() => {
  "use strict";

  const feed = document.getElementById("live-feed");
  if (!feed || typeof EventSource === "undefined") {
    return;
  }

  const stream = new EventSource("/events/stream");

  stream.addEventListener("alert", (message) => {
    let event;
    try {
      event = JSON.parse(message.data);
    } catch (error) {
      return; // A malformed frame must not break the feed.
    }
    const item = document.createElement("li");
    item.dataset.eventId = event.id;
    item.dataset.severity = event.severity;
    item.className = "event";
    for (const [name, value] of [
      ["severity", event.severity],
      ["type", event.type],
      ["summary", event.summary],
    ]) {
      const span = document.createElement("span");
      span.className = name;
      span.textContent = value; // textContent, never innerHTML: no XSS from the feed.
      item.appendChild(span);
    }
    feed.prepend(item);
    while (feed.children.length > 200) {
      feed.lastElementChild.remove();
    }
  });

  stream.addEventListener("error", () => {
    // EventSource reconnects on its own; just reflect the state in the UI.
    document.body.dataset.stream = stream.readyState === 2 ? "disconnected" : "reconnecting";
  });
})();
