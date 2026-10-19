/* Gilgamesh's own client glue. Deliberately tiny, and deliberately CSP-friendly:
 * no inline <script>, and no inline event handlers — every listener here is registered
 * from this file, which the Content-Security-Policy allows as 'self'.
 *
 * Two pieces live here:
 *   1. the live feed — a ~30-line EventSource client for /events/stream. The
 *      `htmx-ext-sse` extension is *not* used: its licence is undeclared in the npm
 *      metadata and no licence file is present, which fails constraint C1 (open source
 *      only). FastAPI serves SSE natively, so the browser side stays ours.
 *   2. the `liveFeed` Alpine component (the CSP build is vendored, so components are
 *      registered here rather than written as inline `x-data` expressions).
 *
 * The paused/unpaused state travels between the two as DOM events on `document`
 * (`gilgamesh:feed-paused` out, `gilgamesh:feed-pending` back), so neither piece holds
 * a reference to the other and both stay testable in isolation.
 */
(() => {
  "use strict";

  const MAX_BUFFERED = 200;
  const feed = document.getElementById("live-feed");

  /** Build one feed row, matching the server-rendered <li> element for element.
   *
   * The badge markup mirrors dashboard.html: the severity class is what colours the
   * pill, so an unknown severity degrades to the neutral info badge instead of an
   * unstyled one.
   */
  const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);

  function buildItem(event) {
    const item = document.createElement("li");
    const severity = SEVERITIES.has(event.severity) ? event.severity : "info";
    item.className = "event feed-row";
    item.dataset.eventId = event.id;
    item.dataset.severity = severity;

    const link = document.createElement("a");
    link.href = `/alerts/${encodeURIComponent(event.id)}`;

    const badge = document.createElement("span");
    badge.className = `badge badge-${severity}`;
    badge.textContent = severity; // textContent, never innerHTML: no XSS from the feed.
    link.appendChild(badge);

    for (const [name, value] of [
      ["feed-row-type", event.type],
      ["feed-row-summary", event.summary],
    ]) {
      const span = document.createElement("span");
      span.className = name;
      span.textContent = value; // textContent, never innerHTML: no XSS from the feed.
      link.appendChild(span);
    }

    if (typeof event.ts === "string") {
      const parsed = new Date(event.ts);
      if (!Number.isNaN(parsed.getTime())) {
        const time = document.createElement("time");
        time.className = "feed-row-time";
        time.dateTime = event.ts;
        // Seconds precision in UTC, the same shape the template prints server-side.
        time.textContent = `${parsed.toISOString().slice(0, 19)}+00:00`;
        link.appendChild(time);
      }
    }

    item.appendChild(link);
    return item;
  }

  function trim() {
    while (feed.children.length > MAX_BUFFERED) {
      feed.lastElementChild.remove();
    }
  }

  /** Drop the server-rendered empty-state row before the first live item lands,
   * so the card never shows "Nothing recorded yet" and real events together. */
  function insertLive(item) {
    const empty = feed.querySelector(".empty-state");
    if (empty) {
      empty.remove();
    }
    feed.prepend(item);
    trim();
  }

  function connectLiveFeed() {
    if (!feed || typeof EventSource === "undefined") {
      return;
    }

    let paused = false;
    const buffered = [];
    const stream = new EventSource("/events/stream");

    function announcePending() {
      document.dispatchEvent(new CustomEvent("gilgamesh:feed-buffered", { detail: buffered.length }));
    }

    stream.addEventListener("alert", (message) => {
      let event;
      try {
        event = JSON.parse(message.data);
      } catch (error) {
        return; // A malformed frame must not break the feed.
      }
      if (paused) {
        buffered.push(event);
        if (buffered.length > MAX_BUFFERED) {
          buffered.shift();
        }
        announcePending();
        return;
      }
      insertLive(buildItem(event));
    });

    document.addEventListener("gilgamesh:feed-paused", (message) => {
      paused = Boolean(message.detail);
      if (paused) {
        return;
      }
      // Newest first, and never more than the buffer holds.
      for (const event of buffered.splice(0).reverse()) {
        insertLive(buildItem(event));
      }
      announcePending();
    });

    stream.addEventListener("error", () => {
      // EventSource reconnects on its own; just reflect the state in the UI.
      document.body.dataset.stream = stream.readyState === 2 ? "disconnected" : "reconnecting";
    });
  }

  function registerComponents() {
    if (!window.Alpine) {
      return;
    }
    // The CSP build evaluates attributes as property paths or method calls only — no
    // inline expressions and no operators — hence the small methods and getters here.
    window.Alpine.data("liveFeed", () => ({
      paused: false,
      buffered: 0,
      init() {
        document.addEventListener("gilgamesh:feed-buffered", (message) => {
          this.buffered = Number(message.detail) || 0;
        });
      },
      toggle() {
        this.paused = !this.paused;
        if (!this.paused) {
          this.buffered = 0;
        }
        document.dispatchEvent(new CustomEvent("gilgamesh:feed-paused", { detail: this.paused }));
      },
      get buttonLabel() {
        return this.paused ? "Resume live feed" : "Pause live feed";
      },
      get indicatorLabel() {
        return this.paused ? "Paused" : "Live";
      },
      get bufferedLabel() {
        return `+${this.buffered} while paused`;
      },
      get noBuffered() {
        return this.buffered === 0;
      },
    }));
  }

  document.addEventListener("alpine:init", registerComponents);
  connectLiveFeed();
})();
