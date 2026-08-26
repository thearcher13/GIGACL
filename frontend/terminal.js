/* GIGACL interactive switch terminal windows. */
'use strict';

(() => {
  const workspaces = new Map();
  let zCounter = 170;

  const allSwitchIds = () => new Set(
    [...workspaces.values()].flatMap(state => state.switches.map(sw => sw.id)));

  const rootStates = () => [...workspaces.values()].filter(state => state.ownsRoot !== false);
  const groupSwitchIds = state => [
    ...state.switches,
    ...(state.peerWorkspace?.switches || []),
  ].map(sw => sw.id);
  const areVpcPeers = (first, second) => !!(
    first && second && first.switch_type === 'nexus' && second.switch_type === 'nexus' &&
    first.vpc_peer_id === second.id && second.vpc_peer_id === first.id);
  const groupsAreVpcRelated = (first, second) => groupSwitchIds(first).some(firstId =>
    groupSwitchIds(second).some(secondId => areVpcPeers(swById(firstId), swById(secondId))));

  function minimizeWindow(state) {
    if (!state?.root || state.root.classList.contains('is-minimized')) return;
    state.root.classList.add('is-minimized');
    state.root.classList.remove('is-fullscreen');
    syncControls(state);
  }

  function minimizeOtherWindows(active) {
    rootStates().forEach(state => {
      if (state !== active && !groupsAreVpcRelated(state, active)) minimizeWindow(state);
    });
    layoutMinimized();
  }

  function reconcileSelection(selectedIds) {
    const ids = new Set(selectedIds || []);
    rootStates().forEach(state => {
      const related = groupSwitchIds(state).some(id => ids.has(id)) ||
        groupSwitchIds(state).some(openId => [...ids].some(selectedId =>
          areVpcPeers(swById(openId), swById(selectedId))));
      if (!related) minimizeWindow(state);
    });
    layoutMinimized();
  }

  function layoutMinimized() {
    const minimized = [...workspaces.values()].filter(state =>
      state.ownsRoot !== false && state.root?.classList.contains('is-minimized'));
    if (!minimized.length) return;
    const gap = 8;
    const minWidth = 180;
    const maxWidth = 270;
    const columns = Math.min(minimized.length,
      Math.max(1, Math.floor((window.innerWidth - gap) / (minWidth + gap))));
    const itemWidth = Math.min(maxWidth,
      Math.floor((window.innerWidth - gap * (columns + 1)) / columns));
    minimized.forEach((state, index) => {
      const column = index % columns;
      const row = Math.floor(index / columns);
      const right = gap + column * (itemWidth + gap);
      const bottom = gap + row * 56;
      state.root.style.setProperty('--terminal-dock-width', `${itemWidth}px`);
      state.root.style.setProperty('--terminal-dock-right', `${right}px`);
      state.root.style.setProperty('--terminal-dock-bottom', `${bottom}px`);
      state.root.style.right = `${right}px`;
      state.root.style.bottom = `${bottom}px`;
    });
  }

  function restorePlacement(state) {
    state.root.style.removeProperty('--terminal-dock-width');
    state.root.style.removeProperty('--terminal-dock-right');
    state.root.style.removeProperty('--terminal-dock-bottom');
    state.root.style.right = `${18 + state.offset}px`;
    state.root.style.bottom = `${18 + state.offset}px`;
  }

  function send(state, message) {
    if (state.socket?.readyState === WebSocket.OPEN) {
      state.socket.send(JSON.stringify(message));
    }
  }

  function sendInput(state, sourceIndex, data) {
    if (!state.syncInput) {
      send(state, { type: 'input', terminal: sourceIndex, data });
      return;
    }
    const linked = state.peerWorkspace ? [state, state.peerWorkspace] : [state];
    linked.forEach(workspace => workspace.entries.forEach((entry, index) => {
      if (entry.status === 'connected')
        send(workspace, { type: 'input', terminal: index, data });
    }));
  }

  function setSync(state, enabled) {
    const linked = state.peerWorkspace ? [state, state.peerWorkspace] : [state];
    linked.forEach(workspace => {
      workspace.syncInput = enabled;
      workspace.syncButton.classList.toggle('is-active', enabled);
      workspace.syncButton.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      workspace.syncButton.title = enabled
        ? 'Synchronized input is on — click to disable'
        : 'Synchronize input between both VPC terminals';
    });
  }

  function linkVpcWindows(first, second) {
    if (!areVpcPeers(swById(first.switches[0]?.id), swById(second.switches[0]?.id)))
      return false;
    first.peerWorkspace = second;
    second.peerWorkspace = first;
    first.syncButton.hidden = false;
    setSync(first, true);

    first.root.classList.remove('is-minimized', 'is-fullscreen');
    restorePlacement(first);
    syncControls(first);
    second.resizeObserver?.disconnect();
    second.entries.forEach(entry => first.body.appendChild(entry.pane));
    second.root.remove();
    second.root = first.root;
    second.body = first.body;
    second.ownsRoot = false;
    first.root.classList.add('has-dual');
    first.body.style.setProperty('--terminal-count', '2');
    el('.terminal-head-copy span', first.root).textContent =
      [...first.switches, ...second.switches].map(sw => sw.name).join(' · ');
    requestAnimationFrame(() => {
      fit(first);
      second.entries[0]?.term.focus();
    });
    return true;
  }

  function fit(state) {
    if (!state.root || state.root.classList.contains('is-minimized')) return;
    const linked = state.peerWorkspace ? [state, state.peerWorkspace] : [state];
    linked.forEach(workspace => workspace.entries.forEach(entry => {
      try { entry.fit.fit(); } catch { /* layout is still settling */ }
    }));
  }

  function focusTerminal(state) {
    requestAnimationFrame(() => {
      if (!state.root || state.closing) return;
      if (state.root.classList.contains('is-minimized')) {
        state.root.tabIndex = -1;
        state.root.focus({ preventScroll:true });
        return;
      }
      const active = state.root._terminalActive;
      const fallback = state.entries[0] || state.peerWorkspace?.entries[0];
      (active?.entry || fallback)?.term.focus();
    });
  }

  function syncControls(state) {
    const minimized = state.root.classList.contains('is-minimized');
    const fullscreen = state.root.classList.contains('is-fullscreen');
    state.minButton.textContent = minimized ? '▢' : '—';
    state.minButton.title = minimized ? 'Restore terminal' : 'Minimize terminal';
    state.maxButton.textContent = fullscreen ? '❐' : '□';
    state.maxButton.title = fullscreen ? 'Exit full screen' : 'Enter full screen';
  }

  function setStatus(state, index, status, message) {
    const entry = state.entries[index];
    if (!entry) return;
    entry.status = status;
    entry.dot.className = `terminal-status-dot ${status}`;
    if (status === 'connected') {
      entry.overlay.hidden = true;
      setTimeout(() => entry.term.focus(), 20);
    } else {
      entry.overlay.hidden = false;
      entry.overlay.textContent = message || (status === 'connecting'
        ? 'Connecting…' : 'SSH connection closed.');
    }
  }

  function dispose(state) {
    state.resizeObserver?.disconnect();
    state.entries.forEach(entry => {
      try { entry.term.dispose(); } catch { /* already disposed */ }
      if (state.ownsRoot === false) entry.pane?.remove();
    });
    state.entries = [];
    if (state.ownsRoot !== false) state.root?.remove();
  }

  async function closeWorkspace(state) {
    if (!state || state.closing) return;
    state.closing = true;
    send(state, { type: 'close' });
    try { state.socket?.close(1000, 'Terminal closed by user'); } catch { /* closed */ }
    let release = null;
    if (state.sessionId && S.token) {
      release = fetch(`/api/terminal/sessions/${encodeURIComponent(state.sessionId)}`, {
        method: 'DELETE', headers: { Authorization: `Bearer ${S.token}` },
      }).catch(() => null);
    }
    workspaces.delete(state.sessionId);
    dispose(state);
    layoutMinimized();
    if (release) await release;
  }

  function close(state) {
    if (!state || state.closing) return;
    const peer = state.peerWorkspace;
    state.peerWorkspace = null;
    if (peer) peer.peerWorkspace = null;
    void Promise.all([state, peer].filter(Boolean).map(closeWorkspace));
  }

  window.closeAllTerminalWindows = function () {
    [...workspaces.values()].forEach(close);
  };

  function createWindow(response) {
    const dual = response.switches.length === 2;
    const state = {
      sessionId: response.session_id, switches: response.switches,
      socket: null, entries: [], syncInput: false, closing: false,
      resizeObserver: null, root: null, peerWorkspace: null, ownsRoot: true,
    };
    const offset = workspaces.size * 30;
    const root = document.createElement('section');
    root.className = `terminal-window${dual ? ' has-dual' : ''}`;
    root.setAttribute('aria-label', 'Switch SSH terminal');
    root.style.right = `${18 + offset}px`;
    root.style.bottom = `${18 + offset}px`;
    root.style.setProperty('--terminal-offset', `${offset}px`);
    root.style.zIndex = String(++zCounter);
    root.innerHTML = `
      <header class="terminal-head">
        <div class="terminal-head-mark">›_</div>
        <div class="terminal-head-copy"><strong>Switch Terminal</strong>
          <span>${response.switches.map(sw => esc(sw.name)).join(' · ')}</span></div>
        <div class="terminal-window-actions">
          <button type="button" class="terminal-sync" ${dual ? '' : 'hidden'}
                  title="Synchronize input between both VPC terminals" aria-label="Synchronize VPC terminal input" aria-pressed="false">⇄</button>
          <button type="button" class="terminal-min" title="Minimize terminal" aria-label="Minimize terminal">—</button>
          <button type="button" class="terminal-max" title="Enter full screen" aria-label="Enter terminal full screen">□</button>
          <button type="button" class="terminal-close" title="Close SSH session" aria-label="Close terminal">✕</button>
        </div>
      </header>
      <div class="terminal-body" style="--terminal-count:${response.switches.length}"></div>`;
    $('terminal-layer').appendChild(root);
    state.root = root;
    state.offset = offset;
    state.body = el('.terminal-body', root);
    state.minButton = el('.terminal-min', root);
    state.maxButton = el('.terminal-max', root);
    state.syncButton = el('.terminal-sync', root);
    workspaces.set(state.sessionId, state);
    if (dual) setSync(state, true);

    root.addEventListener('mousedown', () => { root.style.zIndex = String(++zCounter); });
    state.minButton.addEventListener('click', () => {
      if (root.classList.contains('is-minimized')) minimizeOtherWindows(state);
      const minimized = root.classList.toggle('is-minimized');
      if (minimized) root.classList.remove('is-fullscreen');
      else restorePlacement(state);
      syncControls(state);
      layoutMinimized();
      requestAnimationFrame(() => { fit(state); focusTerminal(state); });
    });
    state.maxButton.addEventListener('click', () => {
      minimizeOtherWindows(state);
      root.classList.remove('is-minimized');
      restorePlacement(state);
      root.classList.toggle('is-fullscreen');
      syncControls(state);
      layoutMinimized();
      requestAnimationFrame(() => { fit(state); focusTerminal(state); });
    });
    el('.terminal-close', root).addEventListener('click', () => close(state));
    state.syncButton.addEventListener('click', () => {
      setSync(state, !state.syncInput);
      state.entries[0]?.term.focus();
    });
    el('.terminal-head', root).addEventListener('dblclick', event => {
      if (!event.target.closest('button')) state.maxButton.click();
    });
    return state;
  }

  function buildPanes(state) {
    state.body.innerHTML = state.switches.map((sw, index) => `
      <div class="terminal-pane" data-terminal="${index}">
        <div class="terminal-pane-head"><span class="terminal-status-dot connecting"></span>
          <strong>${esc(sw.name)}</strong><span class="terminal-ip">${esc(sw.ip)}</span></div>
        <div class="terminal-surface"></div>
        <div class="terminal-overlay">Preparing secure terminal…</div>
      </div>`).join('');

    state.entries = state.switches.map((sw, index) => {
      const pane = el(`.terminal-pane[data-terminal="${index}"]`, state.body);
      const term = new window.Terminal({
        cursorBlink: true, cursorStyle: 'block', convertEol: true,
        fontFamily: '"JetBrains Mono", Consolas, monospace', fontSize: 13,
        lineHeight: 1.18, scrollback: 5000,
        theme: { background:'#080b12',foreground:'#dce3ef',cursor:'#75e6b4',selectionBackground:'#35445f',
          black:'#111827',brightBlack:'#64748b',red:'#f05b6e',green:'#4ade80',yellow:'#facc15',
          blue:'#60a5fa',magenta:'#c084fc',cyan:'#67e8f9',white:'#e5e7eb' },
      });
      const fitAddon = new window.FitAddon.FitAddon();
      term.loadAddon(fitAddon);
      term.open(el('.terminal-surface', pane));
      const markActive = () => { state.root._terminalActive = { state, entry:state.entries[index] }; };
      pane.addEventListener('mousedown', markActive);

      const nexus = String(sw.switch_type || '').toLowerCase() === 'nexus';
      const keyMap = { Backspace:'\x08', ArrowUp:'\x1b[A', ArrowDown:'\x1b[B',
        ArrowRight:'\x1b[C', ArrowLeft:'\x1b[D', Delete:'\x1b[3~', Home:'\x1b[H', End:'\x1b[F' };
      term.attachCustomKeyEventHandler(event => {
        if (event.type !== 'keydown' || event.altKey || event.metaKey) return true;
        if (event.key === 'Backspace' && event.ctrlKey) {
          sendInput(state, index, '\x17'); // Cisco Ctrl+W: erase previous word.
          return false;
        }
        if (event.ctrlKey) return true;
        // Raw ANSI output lets xterm track NX-OS cursor mode and emit the
        // correct normal/application history sequence for each session.
        if (nexus && ['ArrowUp','ArrowDown','ArrowLeft','ArrowRight'].includes(event.key))
          return true;
        const sequence = keyMap[event.key];
        if (!sequence) return true;
        sendInput(state, index, sequence);
        return false;
      });
      term.onData(data => { markActive(); sendInput(state, index, data); });
      term.onResize(size => send(state, { type:'resize', terminal:index, cols:size.cols, rows:size.rows }));
      return { sw, term, fit:fitAddon, pane, status:'connecting',
        dot:el('.terminal-status-dot', pane), overlay:el('.terminal-overlay', pane) };
    });
    state.resizeObserver = new ResizeObserver(() => requestAnimationFrame(() => fit(state)));
    state.resizeObserver.observe(state.root);
    requestAnimationFrame(() => { fit(state); state.entries[0]?.term.focus(); });
  }

  function connect(state) {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${protocol}//${location.host}/api/terminal/ws/${encodeURIComponent(state.sessionId)}`);
    state.socket = socket;
    socket.addEventListener('open', () => requestAnimationFrame(() => fit(state)));
    socket.addEventListener('message', event => {
      if (state.socket !== socket || state.closing) return;
      let message; try { message = JSON.parse(event.data); } catch { return; }
      const index = Number(message.terminal);
      if (message.type === 'output' && state.entries[index]) state.entries[index].term.write(message.data || '');
      else if (message.type === 'status') {
        setStatus(state, index, message.status, message.message);
        if (message.status === 'error') bad('SSH connection failed', message.message);
        if (state.entries.every(entry => ['error','disconnected'].includes(entry.status))) setTimeout(() => close(state), 900);
      } else if (message.type === 'ended') {
        if (message.message) info('Terminal ended', message.message);
        setTimeout(() => close(state), 250);
      }
    });
    socket.addEventListener('close', () => {
      if (state.socket === socket && !state.closing) setTimeout(() => close(state), 250);
    });
    socket.addEventListener('error', () => {
      if (!state.closing) bad('Terminal connection lost', 'The terminal WebSocket could not connect.');
    });
  }

  async function open() {
    if (!isAdmin()) return bad('Access denied', 'Only administrators can open switch terminals.');
    if (!needSwitch()) return;
    const switches = selected();
    if (switches.length > 2) return bad('Too many switches', 'Select one switch or one VPC pair.');
    if (switches.length === 2 && !areVpcPeers(switches[0], switches[1]))
      return bad('Not a VPC pair', 'Two terminals can only be opened for a configured VPC pair.');
    const opened = allSwitchIds();
    const duplicate = switches.find(sw => opened.has(sw.id));
    if (duplicate) {
      const existing = [...workspaces.values()].find(state =>
        state.switches.some(sw => sw.id === duplicate.id));
      const unopened = switches.filter(sw => !opened.has(sw.id));
      const addingVpcPeer = existing && existing.switches.length === 1 &&
        switches.length === 2 && unopened.length === 1 && areVpcPeers(switches[0], switches[1]);
      if (addingVpcPeer) {
        if (opened.size + 1 > 3) return warn('Terminal limit reached',
          'Close another terminal before adding the VPC peer.');
        const missing = unopened.find(sw => !sw.has_saved_password);
        if (missing) return bad('Saved password required',
          `Save the SSH password for ${missing.hostname || missing.ip_address} first.`);
        if (!window.Terminal || !window.FitAddon?.FitAddon)
          return bad('Terminal unavailable', 'The local terminal renderer could not be loaded.');
        const button = $('btn-terminal');
        setBusy(button, true, 'Adding peer…');
        try {
          // Keep the existing SSH session untouched and open only its peer.
          const response = await api('POST', '/api/terminal/sessions', {
            switch_ids:unopened.map(sw => sw.id),
          });
          const peerState = createWindow(response);
          buildPanes(peerState);
          connect(peerState);
          linkVpcWindows(existing, peerState);
        } catch (error) {
          reportError(error, 'Could not add the VPC peer terminal');
        } finally { setBusy(button, false); }
        return;
      }
      if (existing) {
        const windowState = existing.ownsRoot === false
          ? existing.peerWorkspace : existing;
        if (windowState.root.classList.contains('is-minimized')) {
          minimizeOtherWindows(windowState);
          windowState.root.classList.remove('is-minimized');
          restorePlacement(windowState);
          syncControls(windowState);
          layoutMinimized();
          requestAnimationFrame(() => fit(windowState));
        }
        windowState.root.style.zIndex = String(++zCounter);
        existing.entries.find(entry => entry.sw.id === duplicate.id)?.term.focus();
      }
      return;
    }
    if (opened.size + switches.length > 3) return warn('Terminal limit reached',
      'You can have at most three switch terminals open. Close another terminal first.');
    const missing = switches.find(sw => !sw.has_saved_password);
    if (missing) return bad('Saved password required', `Save the SSH password for ${missing.hostname || missing.ip_address} first.`);
    if (!window.Terminal || !window.FitAddon?.FitAddon) return bad('Terminal unavailable', 'The local terminal renderer could not be loaded.');

    const button = $('btn-terminal');
    setBusy(button, true, 'Opening…');
    try {
      const response = await api('POST', '/api/terminal/sessions', { switch_ids:S.swIds });
      const state = createWindow(response);
      minimizeOtherWindows(state);
      buildPanes(state);
      connect(state);
    } catch (error) {
      reportError(error, 'Could not open the terminal');
    } finally { setBusy(button, false); }
  }

  document.addEventListener('DOMContentLoaded', () => $('btn-terminal').addEventListener('click', open));
  document.addEventListener('giga:switch-selection-change', event =>
    reconcileSelection(event.detail?.switchIds));
  window.addEventListener('resize', layoutMinimized);
})();
