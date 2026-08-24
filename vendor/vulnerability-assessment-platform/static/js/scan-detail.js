(function initScanDetailPage() {
  const configElement = document.getElementById("scan-detail-config");
  if (!configElement) {
    return;
  }

  const config = JSON.parse(configElement.textContent || "{}");
  const scanId = Number(config.scanId);
  const apiKey = config.apiKey || "";
  const terminalStatuses = ["completed", "report_failed", "canceled"];
  const initialStatus = config.scanStatus || "";

  if (!Number.isFinite(scanId)) {
    return;
  }

  // If the scan is already in a terminal state when the page loads,
  // skip the WebSocket connection entirely to avoid an infinite reload loop.
  if (terminalStatuses.includes(initialStatus)) {
    return;
  }

  const statusEl = document.getElementById("scan-status");
  const progressBar = document.getElementById("scan-progress-bar");
  const progressValue = document.getElementById("scan-progress-value");
  const logsContainer = document.getElementById("scan-logs");
  const notificationsContainer = document.getElementById("scan-notifications");
  const cancelButton = document.getElementById("cancel-scan");
  const wsStatusEl = document.getElementById("ws-status");
  const spinnerEl = document.getElementById("scan-spinner");
  const initialProgress = Number(progressBar?.dataset?.progress ?? 0);

  if (Number.isFinite(initialProgress) && progressBar && progressValue) {
    const normalized = Math.min(100, Math.max(0, initialProgress));
    progressBar.style.width = `${normalized}%`;
    progressValue.textContent = String(normalized);
  }

  const updateWsStatus = (state, attempt) => {
    if (!wsStatusEl) return;
    const states = {
      connecting: { text: "Connessione...", cls: "text-slate-400" },
      connected: { text: "Connesso", cls: "text-cyan-300" },
      reconnecting: { text: `Riconnessione (tentativo ${attempt || ""})...`, cls: "text-amber-300" },
      closed: { text: "Disconnesso — aggiorna la pagina.", cls: "text-rose-300" },
    };
    const s = states[state] || states.connecting;
    wsStatusEl.textContent = s.text;
    wsStatusEl.className = `text-xs ${s.cls}`;
  };

  const renderEmptyState = (container, message) => {
    container.textContent = "";
    const paragraph = document.createElement("p");
    paragraph.className = "text-slate-500";
    paragraph.textContent = message;
    container.appendChild(paragraph);
  };

  const _buildLogLine = (entry) => {
    const line = document.createElement("p");
    const level = (entry.level || "info").toUpperCase();
    const levelColor = level === "ERROR" ? "text-red-400" : level === "WARNING" ? "text-yellow-400" : "text-cyan-400";

    line.appendChild(document.createTextNode(`[${entry.timestamp || "--"}] `));
    const levelSpan = document.createElement("span");
    levelSpan.className = levelColor;
    levelSpan.textContent = level;
    line.appendChild(levelSpan);
    line.appendChild(document.createTextNode(` — ${entry.message || ""}`));
    return line;
  };

  let lastRenderedLogCount = 0;

  const renderLogs = (logs) => {
    if (!logs.length) {
      lastRenderedLogCount = 0;
      renderEmptyState(logsContainer, "Nessun log disponibile.");
      return;
    }

    // First render: clear server-side static content and build from scratch
    if (lastRenderedLogCount === 0) {
      logsContainer.textContent = "";
      logs.forEach((entry) => logsContainer.appendChild(_buildLogLine(entry)));
      lastRenderedLogCount = logs.length;
      logsContainer.scrollTop = logsContainer.scrollHeight;
      return;
    }

    // Incremental: only append new entries to avoid full DOM rebuild on every WS tick
    if (logs.length > lastRenderedLogCount) {
      logs.slice(lastRenderedLogCount).forEach((entry) => logsContainer.appendChild(_buildLogLine(entry)));
      lastRenderedLogCount = logs.length;
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }
  };

  const renderNotifications = (notifications) => {
    notificationsContainer.textContent = "";
    if (!notifications.length) {
      renderEmptyState(notificationsContainer, "In attesa di eventi critici.");
      return;
    }

    notifications.forEach((notification) => {
      const wrapper = document.createElement("div");
      wrapper.className = "rounded-lg border border-rose-400/40 bg-rose-500/10 px-3 py-2";

      const header = document.createElement("div");
      header.className = "flex items-center gap-2";

      const dot = document.createElement("span");
      dot.className = "inline-block w-2 h-2 rounded-full bg-rose-400";

      const title = document.createElement("span");
      title.className = "font-semibold text-rose-200 text-sm";
      title.textContent = notification.title || "Evento critico";

      const severity = document.createElement("span");
      severity.className = "ml-auto text-xs uppercase text-rose-300 font-bold";
      severity.textContent = notification.severity || "high";

      header.append(dot, title, severity);

      const description = document.createElement("p");
      description.className = "text-slate-200 mt-1 text-xs leading-relaxed";
      description.textContent = notification.description || "";

      wrapper.append(header, description);
      notificationsContainer.appendChild(wrapper);
    });
  };

  let socket;
  let reconnectAttempts = 0;
  const maxReconnectAttempts = 5;
  let allowReconnect = true;

  const handlePayload = (payload) => {
    if (payload.status && statusEl) {
      statusEl.textContent = payload.status;
    }

    if (typeof payload.progress === "number" && progressBar && progressValue) {
      progressBar.style.width = `${payload.progress}%`;
      progressValue.textContent = String(payload.progress);
    }

    renderLogs(payload.logs || []);
    renderNotifications(payload.notifications || []);

    if (terminalStatuses.includes(payload.status)) {
      if (cancelButton) {
        cancelButton.disabled = true;
        cancelButton.classList.add("opacity-50", "cursor-not-allowed");
      }
      if (spinnerEl) spinnerEl.remove();
      if (progressBar) progressBar.classList.remove("animate-pulse");
      allowReconnect = false;
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
      if (payload.status === "completed") {
        if (statusEl) statusEl.textContent = "Completata — aggiornamento pagina...";
        setTimeout(() => window.location.reload(), 2000);
      }
    }
  };

  const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${wsProtocol}://${window.location.host}/ws?scan_id=${scanId}${apiKey ? `&api_key=${apiKey}` : ""}`;

  const connectWebSocket = () => {
    updateWsStatus("connecting");
    socket = new WebSocket(wsUrl);

    socket.onmessage = (event) => {
      try {
        handlePayload(JSON.parse(event.data));
      } catch (err) {
        console.error("[VAP WS] Messaggio non valido ricevuto:", err, event.data);
      }
    };

    socket.onopen = () => {
      reconnectAttempts = 0;
      updateWsStatus("connected");
    };

    socket.onclose = () => {
      if (!allowReconnect || reconnectAttempts >= maxReconnectAttempts) {
        updateWsStatus("closed");
        return;
      }
      const delay = Math.min(1000 * 2 ** reconnectAttempts, 10000);
      reconnectAttempts += 1;
      updateWsStatus("reconnecting", reconnectAttempts);
      lastRenderedLogCount = 0;
      setTimeout(connectWebSocket, delay);
    };

    socket.onerror = () => {
      console.error("[VAP WS] Errore connessione WebSocket.");
      socket.close();
    };
  };

  connectWebSocket();

  if (cancelButton) {
    cancelButton.addEventListener("click", async () => {
      cancelButton.disabled = true;
      cancelButton.textContent = "Annullamento...";
      try {
        const response = await fetch(`/api/v1/scans/${scanId}/cancel${apiKey ? `?api_key=${apiKey}` : ""}`, { method: "POST" });
        if (!response.ok) {
          cancelButton.disabled = false;
          cancelButton.textContent = "Annulla scan";
          console.error("[VAP] Annullamento scansione fallito:", response.status);
        }
      } catch (err) {
        cancelButton.disabled = false;
        cancelButton.textContent = "Annulla scan";
        console.error("[VAP] Errore di rete durante annullamento:", err);
      }
    });
  }
})();
