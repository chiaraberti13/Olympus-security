(function () {
  "use strict";

  const tabs = Array.from(document.querySelectorAll("[data-guide-tab]"));
  const panels = Array.from(document.querySelectorAll("[data-guide-panel]"));
  if (tabs.length === 0 || panels.length === 0) {
    return;
  }

  const panelIds = new Set(panels.map((panel) => panel.id));

  function activate(id, options) {
    const opts = options || {};
    if (!panelIds.has(id)) {
      return;
    }
    panels.forEach((panel) => {
      panel.hidden = panel.id !== id;
    });
    tabs.forEach((tab) => {
      const selected = tab.dataset.guideTab === id;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.classList.toggle("guide-tab-active", selected);
      tab.tabIndex = selected ? 0 : -1;
    });
    if (opts.push !== false && window.history && window.history.replaceState) {
      window.history.replaceState(null, "", "#" + id);
    }
    // Each section starts at the top so users never scroll up to find content.
    if (opts.scroll !== false) {
      window.scrollTo({ top: 0, behavior: "auto" });
    }
    if (opts.focusPanel) {
      const target = document.getElementById(id);
      if (target) {
        target.focus({ preventScroll: true });
      }
    }
  }

  // Initial panel: honour the URL hash, otherwise the first tab.
  const initialHash = (window.location.hash || "").replace("#", "");
  const initialId = panelIds.has(initialHash) ? initialHash : panels[0].id;
  activate(initialId, { push: false, scroll: false });

  tabs.forEach((tab) => {
    tab.addEventListener("click", (event) => {
      event.preventDefault();
      activate(tab.dataset.guideTab);
    });
  });

  // In-content shortcuts (e.g. overview cards) that jump to another section.
  document.querySelectorAll("[data-guide-jump]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      activate(link.dataset.guideJump, { focusPanel: true });
    });
  });

  // Roving keyboard navigation across the tablist (WAI-ARIA tabs pattern).
  const tablist = document.getElementById("guide-tabs");
  if (tablist) {
    tablist.addEventListener("keydown", (event) => {
      const current = tabs.findIndex(
        (tab) => tab.getAttribute("aria-selected") === "true"
      );
      if (current < 0) {
        return;
      }
      let next = null;
      if (event.key === "ArrowRight" || event.key === "ArrowDown") {
        next = (current + 1) % tabs.length;
      } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
        next = (current - 1 + tabs.length) % tabs.length;
      } else if (event.key === "Home") {
        next = 0;
      } else if (event.key === "End") {
        next = tabs.length - 1;
      }
      if (next === null) {
        return;
      }
      event.preventDefault();
      const tab = tabs[next];
      activate(tab.dataset.guideTab);
      tab.focus();
    });
  }
})();
