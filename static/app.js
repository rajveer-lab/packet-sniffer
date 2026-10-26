// Built by tools/build.py from static/app.jsx (sha256 0ae36df4f90a61b4e3477875bbb2202271d20eca83c0e562b17933c99a84c801).
// Do not edit: change app.jsx, then run  python tools/build.py dashboard
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const {
  useEffect,
  useLayoutEffect,
  useRef,
  useState
} = React;
const POLL_MS = 1000;
const KEEP_ROWS = 300;
const SHOW_ROWS = 150;
const PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "Other"];
const NO_FILTERS = {
  proto: "",
  host: "",
  port: "",
  q: ""
};
const SEVERITY_LABEL = {
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW"
};
function formatBytes(n) {
  if (n == null) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}
function formatTime(epochSeconds) {
  return new Date(epochSeconds * 1000).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
}
function formatDuration(seconds) {
  const s = Math.floor(seconds || 0);
  const m = Math.floor(s / 60);
  return m ? `${m}m ${s % 60}s` : `${s}s`;
}
function formatRetention(seconds) {
  if (!seconds) return "";
  return seconds % 60 === 0 ? `${seconds / 60} min` : `${seconds} s`;
}
function protoClass(proto) {
  return ["TCP", "UDP", "ICMP", "ARP"].includes(proto) ? proto : "Other";
}
function withPort(host, port) {
  return port == null ? host || "-" : `${host}:${port}`;
}
function filterQuery(filters) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (String(value).trim()) params.set(key, String(value).trim());
  }
  return params.toString();
}
async function getJSON(url) {
  const response = await fetch(url, {
    cache: "no-store"
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const err = new Error(body?.error || `${url} returned ${response.status}`);
    err.status = response.status;
    throw err;
  }
  return body;
}
function usePolling(filters) {
  const [packets, setPackets] = useState([]);
  const [stats, setStats] = useState(null);
  const [security, setSecurity] = useState(null);
  const [offline, setOffline] = useState(false);
  const [paused, setPaused] = useState(false);
  const [filterError, setFilterError] = useState(null);
  const lastId = useRef(0);
  const retention = useRef(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const query = filterQuery(filters);
  const queryRef = useRef(query);
  const reload = useRef(false);
  const tickRef = useRef(null);
  useEffect(() => {
    if (queryRef.current === query) return;
    queryRef.current = query;
    lastId.current = 0;
    reload.current = true;
    setPackets([]);
    tickRef.current?.();
  }, [query]);
  useEffect(() => {
    let stopped = false;
    let busy = false;
    async function fetchPackets() {
      const asked = queryRef.current;
      const url = `/api/packets?after=${lastId.current}&limit=${SHOW_ROWS}${asked ? "&" + asked : ""}`;
      let p;
      try {
        p = await getJSON(url);
      } catch (err) {
        if (err.status !== 400) throw err;
        if (!stopped) setFilterError(err.message);
        return;
      }
      if (stopped || asked !== queryRef.current) return;
      reload.current = false;
      setFilterError(null);
      lastId.current = p.last_id;
      const cutoff = retention.current ? Date.now() / 1000 - retention.current : -Infinity;
      setPackets(prev => [...p.packets.reverse(), ...prev].filter(r => r.time >= cutoff).slice(0, KEEP_ROWS));
    }
    async function tick() {
      if (busy) return;
      busy = true;
      try {
        const [s, a] = await Promise.all([getJSON("/api/stats"), getJSON("/api/alerts")]);
        retention.current = s.retention;
        if (s.last_id < lastId.current) {
          lastId.current = 0;
          setPackets([]);
        }
        if (!pausedRef.current || reload.current) await fetchPackets();
        if (!stopped) {
          setStats(s);
          setSecurity(a);
          setOffline(false);
        }
      } catch (err) {
        if (err.status === 401) window.location.reload();else if (!stopped) setOffline(true);
      } finally {
        busy = false;
      }
    }
    tickRef.current = tick;
    tick();
    const timer = setInterval(tick, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, []);
  const refresh = () => tickRef.current?.();
  return {
    packets,
    stats,
    security,
    offline,
    paused,
    setPaused,
    filterError,
    refresh
  };
}
function useWidth() {
  const ref = useRef(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const observer = new ResizeObserver(entries => setWidth(entries[0].contentRect.width));
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}
function StatusPill({
  capture,
  offline
}) {
  if (offline) {
    return React.createElement("div", {
      className: "status error"
    }, React.createElement("span", {
      className: "dot"
    }), React.createElement("b", null, "OFFLINE"), " sniffer.py is not running");
  }
  if (!capture) return React.createElement("div", {
    className: "status"
  }, React.createElement("span", {
    className: "dot"
  }), "Connecting\u2026");
  if (capture.error) {
    return React.createElement("div", {
      className: "status error"
    }, React.createElement("span", {
      className: "dot"
    }), React.createElement("b", null, "STOPPED"), " ", capture.source);
  }
  if (capture.stopped && !capture.running) {
    return React.createElement("div", {
      className: "status"
    }, React.createElement("span", {
      className: "dot"
    }), React.createElement("b", null, "STOPPED"), " ", capture.stopped);
  }
  if (capture.mode === "replay") {
    const file = (capture.source || "").split(/[\\/]/).pop();
    return React.createElement("div", {
      className: "status replay"
    }, React.createElement("span", {
      className: "dot"
    }), React.createElement("b", null, capture.running ? "REPLAY" : "REPLAY DONE"), " ", file);
  }
  return React.createElement("div", {
    className: "status live"
  }, React.createElement("span", {
    className: "dot"
  }), React.createElement("b", null, "LIVE"), " Capturing on ", capture.source, capture.filter ? ` · filter: ${capture.filter}` : "");
}
function Banners({
  capture,
  security,
  onFocus
}) {
  const high = (security?.alerts || []).filter(a => a.severity === "high");
  const saving = capture?.saving;
  return React.createElement(React.Fragment, null, high.length > 0 && React.createElement("div", {
    className: "banner danger"
  }, React.createElement("span", {
    className: "tag"
  }, "SECURITY"), React.createElement("span", null, high.length, " high-severity alert", high.length > 1 ? "s" : "", ". Latest:", " ", React.createElement("button", {
    className: "link",
    onClick: () => onFocus(high[0].focus)
  }, high[0].title))), capture?.error && React.createElement("div", {
    className: "banner error"
  }, React.createElement("span", {
    className: "tag"
  }, "CAPTURE"), React.createElement("span", null, capture.error)), capture?.stopped && !capture.running && !capture.error && React.createElement("div", {
    className: "banner info"
  }, React.createElement("span", {
    className: "tag"
  }, "STOPPED"), React.createElement("span", null, "Capture stopped by itself (", capture.stopped, ") after ", capture.captured.toLocaleString(), " packets. Run sniffer.py again to capture more.")), capture?.mode === "replay" && !capture.error && !capture.stopped && React.createElement("div", {
    className: "banner info"
  }, React.createElement("span", {
    className: "tag"
  }, "REPLAY"), React.createElement("span", null, "Showing packets from a saved capture file, not live traffic. Run without --pcap to capture live.")), saving && React.createElement("div", {
    className: `banner ${saving.error ? "error" : "saved"}`
  }, React.createElement("span", {
    className: "tag"
  }, "SAVING"), React.createElement("span", null, saving.error || React.createElement(React.Fragment, null, "Packets are saved in ", React.createElement("code", null, saving.folder), ": ", saving.files, " file", saving.files === 1 ? "" : "s", ",", " ", formatBytes(saving.bytes), ". A new file starts every ", saving.max_mb, " MB and only the newest", " ", saving.keep_files, " are kept", saving.deleted ? ` (${saving.deleted} older deleted)` : "", "."))));
}
function Summary({
  stats
}) {
  const s = stats || {};
  const items = [{
    label: "Packets captured",
    value: (s.total_packets ?? 0).toLocaleString(),
    sub: `in ${formatDuration(s.uptime)}`
  }, {
    label: "Data captured",
    value: formatBytes(s.total_bytes ?? 0),
    sub: "on the wire, all layers"
  }, {
    label: "Speed now",
    value: `${formatBytes(s.bytes_per_sec ?? 0)}/s`,
    sub: "during the last full second"
  }, {
    label: "Packets / sec",
    value: (s.packets_per_sec ?? 0).toLocaleString(),
    sub: s.capture?.dropped ? `${s.capture.dropped} dropped` : "none dropped"
  }];
  return React.createElement("div", {
    className: "summary"
  }, items.map(item => React.createElement("div", {
    className: "metric",
    key: item.label
  }, React.createElement("div", {
    className: "label"
  }, item.label), React.createElement("div", {
    className: "value"
  }, item.value), React.createElement("div", {
    className: "sub"
  }, item.sub))));
}
function bandwidthScale(maxBytes) {
  maxBytes = Math.max(maxBytes, 1024);
  const units = [["B", 1], ["KB", 1024], ["MB", 1024 ** 2], ["GB", 1024 ** 3]];
  let [unit, size] = units[0];
  for (const u of units) if (maxBytes >= u[1]) [unit, size] = u;
  const value = Math.max(maxBytes / size, 1);
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const top = [1, 2, 5, 10].map(m => m * magnitude).find(v => v >= value);
  const label = v => v === 0 ? "0" : `${+v.toFixed(1)} ${unit}/s`;
  return {
    top: top * size,
    ticks: [0, top / 2, top].map(v => ({
      value: v * size,
      label: label(v)
    }))
  };
}
function spreadLabels(items, minGap, top, bottom) {
  const sorted = [...items].sort((a, b) => a.y - b.y);
  for (let i = 1; i < sorted.length; i++) sorted[i].y = Math.max(sorted[i].y, sorted[i - 1].y + minGap);
  const overflow = sorted.length ? sorted[sorted.length - 1].y - bottom : 0;
  if (overflow > 0) sorted.forEach(s => {
    s.y = Math.max(top, s.y - overflow);
  });
  return sorted;
}
function BandwidthChart({
  points,
  apps,
  appsEnabled
}) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState(null);
  const [mode, setMode] = useState("total");
  const byProgram = mode === "programs";
  const totals = (points || []).slice(0, -1);
  const appPoints = (apps?.points || []).slice(0, -1);
  const series = byProgram ? (apps?.apps || []).map((app, i) => ({
    key: app,
    label: app,
    cls: `s${i + 1}`,
    values: appPoints.map(p => p.bytes[app] || 0)
  })) : [{
    key: "total",
    label: "All traffic",
    cls: "s-total",
    values: totals.map(d => d.bytes)
  }];
  const times = byProgram ? appPoints.map(p => p.t) : totals.map(d => d.t);
  const n = times.length;
  const H = 180;
  const M = {
    top: 12,
    right: byProgram ? 132 : 14,
    bottom: 26,
    left: 70
  };
  const innerW = Math.max(0, width - M.left - M.right);
  const innerH = H - M.top - M.bottom;
  const peak = Math.max(0, ...series.flatMap(s => s.values));
  const scale = bandwidthScale(peak);
  const x = i => M.left + (n > 1 ? i / (n - 1) * innerW : 0);
  const y = v => M.top + innerH - v / scale.top * innerH;
  const path = values => values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const marks = [0, 15, 30, 45].map(ago => n - 1 - ago).filter(i => i >= 0);
  const h = hover != null && hover < n ? hover : null;
  const labels = byProgram && n ? spreadLabels(series.map(s => ({
    key: s.key,
    label: s.label,
    cls: s.cls,
    y: y(s.values[n - 1])
  })), 13, M.top, M.top + innerH) : [];
  function onPointer(e) {
    if (!n || !innerW) return;
    const px = e.clientX - e.currentTarget.getBoundingClientRect().left;
    const i = Math.round((px - M.left) / innerW * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  }
  function onKey(e) {
    if (!n) return;
    if (e.key === "ArrowLeft") setHover(i => Math.max(0, (i ?? n) - 1));else if (e.key === "ArrowRight") setHover(i => Math.min(n - 1, (i ?? -1) + 1));else if (e.key === "Escape") setHover(null);else return;
    e.preventDefault();
  }
  const empty = byProgram ? appsEnabled === false ? "Programs are named during live capture only" : "No program traffic in the last minute" : "No traffic in the last minute";
  return React.createElement("div", {
    className: "card chart-card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", null, React.createElement("div", {
    className: "label"
  }, "Bandwidth"), React.createElement("div", {
    className: "muted"
  }, "Bytes per second over the last minute", byProgram ? ", busiest programs" : "")), React.createElement("div", {
    className: "chart-head-right"
  }, React.createElement("span", {
    className: "muted"
  }, "peak ", formatBytes(peak), "/s"), React.createElement("div", {
    className: "seg small",
    role: "group",
    "aria-label": "What to show"
  }, [["total", "Total"], ["programs", "By program"]].map(([key, text]) => React.createElement("button", {
    key: key,
    className: mode === key ? "on" : "",
    "aria-pressed": mode === key,
    onClick: () => {
      setMode(key);
      setHover(null);
    }
  }, text))))), React.createElement("div", {
    className: "chart",
    ref: ref,
    tabIndex: 0,
    "aria-label": "Bandwidth over the last minute. Use the arrow keys to read each second.",
    onPointerMove: onPointer,
    onPointerLeave: () => setHover(null),
    onFocus: () => setHover(i => i ?? n - 1),
    onBlur: () => setHover(null),
    onKeyDown: onKey
  }, width > 0 && React.createElement("svg", {
    width: width,
    height: H,
    "aria-hidden": "true"
  }, scale.ticks.map(t => React.createElement("g", {
    key: t.value
  }, React.createElement("line", {
    className: "grid",
    x1: M.left,
    x2: width - M.right,
    y1: y(t.value),
    y2: y(t.value)
  }), React.createElement("text", {
    className: "axis",
    x: M.left - 10,
    y: y(t.value),
    dy: "0.32em",
    textAnchor: "end"
  }, t.label))), marks.map(i => React.createElement("text", {
    key: i,
    className: "axis",
    x: x(i),
    y: H - 6,
    textAnchor: i === n - 1 ? "end" : "middle"
  }, i === n - 1 ? "now" : `${n - 1 - i} s ago`)), !byProgram && n > 1 && React.createElement("path", {
    className: "area",
    d: `${path(series[0].values)}L${x(n - 1)},${y(0)}L${x(0)},${y(0)}Z`
  }), series.map(s => React.createElement("path", {
    key: s.key,
    className: `line ${s.cls}`,
    d: path(s.values)
  })), labels.map(l => React.createElement("text", {
    key: l.key,
    className: "end-label",
    x: x(n - 1) + 10,
    y: l.y,
    dy: "0.32em"
  }, l.label.length > 16 ? `${l.label.slice(0, 15)}…` : l.label)), h != null && React.createElement("g", null, React.createElement("line", {
    className: "crosshair",
    x1: x(h),
    x2: x(h),
    y1: M.top,
    y2: M.top + innerH
  }), series.map(s => React.createElement("circle", {
    key: s.key,
    className: `dot ${s.cls}`,
    cx: x(h),
    cy: y(s.values[h]),
    r: "4.5"
  })))), width > 0 && peak === 0 && React.createElement("div", {
    className: "chart-empty"
  }, empty), h != null && React.createElement("div", {
    className: "tooltip",
    style: {
      left: Math.min(Math.max(x(h), 110), width - 110),
      top: 0
    }
  }, series.map(s => React.createElement("span", {
    key: s.key,
    className: "tip-row"
  }, React.createElement("i", {
    className: `key ${s.cls}`,
    "aria-hidden": "true"
  }), React.createElement("b", null, formatBytes(s.values[h]), "/s"), byProgram && React.createElement("em", null, s.label))), React.createElement("span", null, !byProgram && `${totals[h]?.packets.toLocaleString()} packets · `, formatTime(times[h]))), React.createElement("div", {
    className: "sr-only"
  }, React.createElement("table", null, React.createElement("caption", null, "Bytes per second, last minute"), React.createElement("thead", null, React.createElement("tr", null, React.createElement("th", null, "Time"), series.map(s => React.createElement("th", {
    key: s.key
  }, s.label)))), React.createElement("tbody", null, times.map((t, i) => React.createElement("tr", {
    key: t
  }, React.createElement("td", null, formatTime(t)), series.map(s => React.createElement("td", {
    key: s.key
  }, s.values[i])))))))), byProgram && series.length > 0 && React.createElement("div", {
    className: "chart-legend"
  }, series.map(s => React.createElement("span", {
    key: s.key
  }, React.createElement("i", {
    className: `key ${s.cls}`,
    "aria-hidden": "true"
  }), s.label))));
}
function FilterBar({
  filters,
  setFilters,
  error
}) {
  const typed = f => ({
    host: f.host,
    port: f.port,
    q: f.q
  });
  const [draft, setDraft] = useState(typed(filters));
  useEffect(() => setDraft(typed(filters)), [filters.host, filters.port, filters.q]);
  function apply(next = draft) {
    setFilters(f => f.host === next.host && f.port === next.port && f.q === next.q ? f : {
      ...f,
      ...next
    });
  }
  useEffect(() => {
    const timer = setTimeout(() => apply(draft), 400);
    return () => clearTimeout(timer);
  }, [draft]);
  const field = (key, props) => React.createElement("input", _extends({}, props, {
    value: draft[key],
    onChange: e => setDraft(d => ({
      ...d,
      [key]: e.target.value
    })),
    onKeyDown: e => e.key === "Enter" && apply()
  }));
  const active = Object.values(filters).some(v => String(v).trim());
  return React.createElement("div", {
    className: "filters"
  }, React.createElement("div", {
    className: "seg",
    role: "group",
    "aria-label": "Protocol"
  }, ["", ...PROTOCOLS].map(p => React.createElement("button", {
    key: p || "all",
    className: filters.proto === p ? "on" : "",
    "aria-pressed": filters.proto === p,
    onClick: () => setFilters(f => ({
      ...f,
      proto: p
    }))
  }, p || "All"))), React.createElement("div", {
    className: "fields"
  }, field("host", {
    className: "f-host",
    placeholder: "IP, MAC or subnet",
    "aria-label": "Host filter"
  }), field("port", {
    className: "f-port",
    placeholder: "Port",
    inputMode: "numeric",
    "aria-label": "Port filter"
  }), field("q", {
    className: "f-q",
    placeholder: "Search rows",
    "aria-label": "Search packets"
  }), active && React.createElement("button", {
    onClick: () => setFilters(NO_FILTERS)
  }, "Clear")), error && React.createElement("div", {
    className: "filter-error"
  }, error));
}
function PacketTable({
  packets,
  paused,
  setPaused,
  selectedId,
  onSelect,
  filters,
  setFilters,
  filterError,
  retention,
  capturing
}) {
  const wrap = useRef(null);
  const [order, setOrder] = useState("newest");
  const [held, setHeld] = useState(null);
  const live = packets.slice(0, SHOW_ROWS);
  const newestFirst = held || live;
  const rows = order === "newest" ? newestFirst : [...newestFirst].reverse();
  const newer = held ? packets.filter(p => p.id > (held[0]?.id ?? 0)).length : 0;
  const filtered = Object.values(filters).some(v => String(v).trim());
  const kept = retention ? ` · kept for ${formatRetention(retention)}` : "";
  function fromLiveEnd(el) {
    return order === "newest" ? el.scrollTop : el.scrollHeight - el.clientHeight - el.scrollTop;
  }
  function jumpToLiveEnd() {
    const el = wrap.current;
    if (el) el.scrollTop = order === "newest" ? 0 : el.scrollHeight;
  }
  function onScroll(e) {
    const away = fromLiveEnd(e.currentTarget) > 8;
    if (away && !held) setHeld(live);else if (!away && held) setHeld(null);
  }
  function backToLive() {
    setHeld(null);
    jumpToLiveEnd();
  }
  function toggleOrder() {
    setHeld(null);
    setOrder(o => o === "newest" ? "oldest" : "newest");
  }
  useLayoutEffect(jumpToLiveEnd, [order]);
  const lastHeight = useRef(0);
  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    if (order === "oldest") {
      const grew = Math.max(0, el.scrollHeight - lastHeight.current);
      if (fromLiveEnd(el) <= grew + 8) el.scrollTop = el.scrollHeight;
    }
    lastHeight.current = el.scrollHeight;
  }, [rows]);
  useEffect(backToLive, [filterQuery(filters)]);
  const waiting = newer ? ` · ${newer >= KEEP_ROWS ? `${KEEP_ROWS}+` : newer} new packet${newer === 1 ? "" : "s"}` : "";
  return React.createElement("div", {
    className: "card",
    id: "packets"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", null, React.createElement("div", {
    className: "label"
  }, "Live packets"), React.createElement("div", {
    className: "muted"
  }, filtered ? `${rows.length} matching · ` : "", order === "newest" ? "Newest" : "Oldest", " first", kept, " \xB7 click a row to see its headers")), React.createElement("div", {
    className: "head-buttons"
  }, React.createElement("a", {
    className: "button",
    href: `/api/export/packets.csv?${filterQuery(filters)}`,
    download: true,
    title: "Download the packets shown (with the current filters) as a spreadsheet"
  }, "Export CSV"), React.createElement("a", {
    className: "button",
    href: `/api/export/packets.pcap?${filterQuery(filters)}`,
    download: true,
    title: "Download the packets shown as a .pcap file, to open in Wireshark"
  }, "Export .pcap"), React.createElement("button", {
    className: paused ? "paused" : "",
    onClick: () => setPaused(!paused)
  }, paused ? "Resume" : "Pause"))), React.createElement(FilterBar, {
    filters: filters,
    setFilters: setFilters,
    error: filterError
  }), React.createElement("div", {
    className: "table-area"
  }, held && React.createElement("div", {
    className: `held ${order === "newest" ? "at-top" : "at-bottom"}`,
    role: "status"
  }, React.createElement("span", null, "Held still while you scroll", waiting), React.createElement("button", {
    onClick: backToLive
  }, "Back to live")), React.createElement("div", {
    className: "table-wrap",
    ref: wrap,
    onScroll: onScroll
  }, React.createElement("table", null, React.createElement("thead", null, React.createElement("tr", null, React.createElement("th", {
    "aria-sort": order === "newest" ? "descending" : "ascending"
  }, React.createElement("button", {
    className: "sort",
    onClick: toggleOrder,
    title: order === "newest" ? "Showing newest first. Click for oldest first." : "Showing oldest first. Click for newest first."
  }, "TIME ", React.createElement("span", {
    "aria-hidden": "true"
  }, order === "newest" ? "▼" : "▲"))), React.createElement("th", null, "APP"), React.createElement("th", null, "SOURCE"), React.createElement("th", null, "DESTINATION"), React.createElement("th", null, "PROTO"), React.createElement("th", null, "SERVICE"), React.createElement("th", {
    className: "num"
  }, "BYTES"), React.createElement("th", null, "INFO"))), React.createElement("tbody", null, rows.map(p => React.createElement("tr", {
    key: p.id,
    className: [p.id === selectedId ? "selected" : "", p.tcp_note ? "noted" : ""].join(" ").trim(),
    onClick: () => onSelect(p)
  }, React.createElement("td", {
    className: "time"
  }, formatTime(p.time)), React.createElement("td", {
    className: "program",
    title: p.app || "Program not known (another device, or a replayed file)"
  }, p.app || React.createElement("span", {
    className: "none"
  }, "\u2014")), React.createElement("td", null, withPort(p.src, p.sport), p.src_name && React.createElement("span", {
    className: "hostname"
  }, p.src_name)), React.createElement("td", null, withPort(p.dst, p.dport), p.dst_name && React.createElement("span", {
    className: "hostname"
  }, p.dst_name)), React.createElement("td", null, React.createElement("span", {
    className: `badge p-${protoClass(p.proto)}`
  }, p.proto)), React.createElement("td", null, p.service || ""), React.createElement("td", {
    className: "num"
  }, p.length), React.createElement("td", {
    className: "info"
  }, p.info))))), !rows.length && React.createElement("div", {
    className: "empty"
  }, filtered ? "No packets match these filters yet." : capturing ? React.createElement(React.Fragment, null, "Waiting for packets\u2026 open a website to generate some traffic.") : `Capture has stopped, and packets older than ${formatRetention(retention)} have decayed.`))));
}
async function postJSON(url, body = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body),
    cache: "no-store"
  });
  if (response.status === 401) window.location.reload();
  const data = await response.json().catch(() => ({}));
  return {
    ok: response.ok && data.ok !== false,
    ...data
  };
}
function AlertCard({
  alert,
  defense,
  open,
  onToggle,
  onFocus,
  onFix,
  onUndo,
  busy
}) {
  const fixed = alert.fixed;
  const canFix = defense?.available;
  return React.createElement("div", {
    className: `alert${open ? " open" : ""}`
  }, React.createElement("div", {
    className: "alert-head"
  }, React.createElement("span", {
    className: `sev s-${alert.severity}`
  }, SEVERITY_LABEL[alert.severity]), React.createElement("span", {
    className: "title"
  }, alert.title), React.createElement("span", {
    className: "when"
  }, formatTime(alert.last_seen), alert.count > 1 ? ` · ×${alert.count.toLocaleString()}` : "", fixed && React.createElement("span", {
    className: "fixed-tag"
  }, "FIXED")), React.createElement("span", {
    className: "detail"
  }, alert.detail)), React.createElement("div", {
    className: "alert-actions"
  }, React.createElement("button", {
    onClick: () => onFocus(alert.focus)
  }, "Show packets"), alert.advice && React.createElement("button", {
    className: open ? "on" : "",
    "aria-expanded": open,
    onClick: onToggle
  }, open ? "Hide fix" : "How to fix")), open && alert.advice && React.createElement("div", {
    className: "fix"
  }, React.createElement("p", null, alert.advice.meaning), React.createElement("ol", null, alert.advice.steps.map(step => React.createElement("li", {
    key: step
  }, step))), fixed ? React.createElement("div", {
    className: "fix-done"
  }, React.createElement("span", null, "\u2713 ", fixed.label, fixed.auto ? " (automatically)" : ""), React.createElement("button", {
    disabled: busy,
    onClick: () => onUndo(fixed.id)
  }, "Undo")) : alert.fix_label ? React.createElement("div", {
    className: "fix-do"
  }, React.createElement("button", {
    className: "primary",
    disabled: !canFix || busy,
    onClick: () => onFix(alert.id)
  }, busy ? "Working…" : alert.fix_label), !canFix && defense?.reason && React.createElement("span", {
    className: "muted"
  }, defense.reason)) : React.createElement("div", {
    className: "muted"
  }, "No one-click fix for this one: follow the steps above.")));
}
function SecurityPanel({
  security,
  onFocus,
  refresh
}) {
  const [open, setOpen] = useState({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  if (!security) {
    return React.createElement("div", {
      className: "card"
    }, React.createElement("div", {
      className: "card-head"
    }, React.createElement("div", {
      className: "label"
    }, "Security")), React.createElement("div", {
      className: "muted"
    }, "Loading\u2026"));
  }
  if (!security.enabled) {
    return React.createElement("div", {
      className: "card"
    }, React.createElement("div", {
      className: "card-head"
    }, React.createElement("div", {
      className: "label"
    }, "Security")), React.createElement("div", {
      className: "muted"
    }, "Security checks are off. Start without --no-security to turn them on."));
  }
  const {
    alerts,
    rules,
    checked,
    defense
  } = security;
  const applied = defense?.applied || [];
  async function act(url, body) {
    setBusy(true);
    const result = await postJSON(url, body);
    setMessage({
      ok: result.ok,
      text: result.message
    });
    setBusy(false);
    refresh();
  }
  return React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", {
    className: "label"
  }, "Security"), React.createElement("div", {
    className: "muted"
  }, checked.toLocaleString(), " packets checked")), React.createElement("div", {
    className: "checks"
  }, rules.map(rule => React.createElement("div", {
    className: `check ${rule.alerts ? `hit s-${rule.severity}` : "ok"}`,
    key: rule.rule
  }, React.createElement("span", {
    className: "mark",
    "aria-hidden": "true"
  }, rule.alerts ? "!" : "✓"), React.createElement("span", {
    className: "name"
  }, rule.name, React.createElement("small", null, rule.description)), React.createElement("span", {
    className: "state"
  }, rule.alerts ? `${rule.alerts} alert${rule.alerts > 1 ? "s" : ""}` : "OK")))), message && React.createElement("div", {
    className: `fix-message ${message.ok ? "good" : "bad"}`,
    role: "status"
  }, React.createElement("span", null, message.text), React.createElement("button", {
    className: "link",
    onClick: () => setMessage(null)
  }, "Dismiss")), alerts.length === 0 ? React.createElement("div", {
    className: "all-clear"
  }, "No threats detected so far.") : React.createElement("div", {
    className: "alerts"
  }, alerts.map(a => React.createElement(AlertCard, {
    key: a.id,
    alert: a,
    defense: defense,
    open: !!open[a.id],
    onToggle: () => setOpen(o => ({
      ...o,
      [a.id]: !o[a.id]
    })),
    onFocus: onFocus,
    onFix: id => act("/api/defense/apply", {
      alert_id: id
    }),
    onUndo: id => act("/api/defense/undo", {
      fix_id: id
    }),
    busy: busy
  }))), React.createElement("div", {
    className: "protection"
  }, React.createElement("div", {
    className: "protection-head"
  }, React.createElement("span", {
    className: "label"
  }, "Protection"), React.createElement("span", {
    className: "muted"
  }, defense?.auto_block ? "Auto-block on" : "Auto-block off", " · ", React.createElement("a", {
    href: "/api/export/alerts.csv",
    download: true
  }, "Export alerts (CSV)"))), applied.length === 0 ? React.createElement("div", {
    className: "muted"
  }, "No fixes applied.", defense && !defense.available && defense.reason ? ` ${defense.reason}` : "") : applied.map(f => React.createElement("div", {
    className: "applied",
    key: f.id
  }, React.createElement("span", null, f.label, f.auto ? " (auto)" : "", React.createElement("small", null, formatTime(f.time))), React.createElement("button", {
    disabled: busy,
    onClick: () => act("/api/defense/undo", {
      fix_id: f.id
    })
  }, "Undo")))));
}
function CaptureButton({
  capture,
  refresh
}) {
  const [busy, setBusy] = useState(false);
  if (!capture) return null;
  const running = capture.running;
  async function toggle() {
    setBusy(true);
    await postJSON(`/api/capture/${running ? "stop" : "start"}`);
    setBusy(false);
    refresh();
  }
  return React.createElement("button", {
    className: `capture-button ${running ? "stop" : "start"}`,
    disabled: busy,
    onClick: toggle
  }, running ? "Stop capture" : "Start capture");
}
function Protocols({
  protocols,
  retention,
  onPick,
  picked
}) {
  const list = protocols || [];
  return React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", {
    className: "label"
  }, "Protocols"), React.createElement("div", {
    className: "muted"
  }, "share of packets", retention ? `, last ${formatRetention(retention)}` : "")), React.createElement("div", {
    className: "stack"
  }, list.map(p => React.createElement("div", {
    key: p.name,
    className: `c-${protoClass(p.name)}`,
    style: {
      width: `${p.percent}%`
    },
    title: `${p.name} ${p.percent}%`
  }))), React.createElement("div", {
    className: "legend"
  }, list.map(p => React.createElement("button", {
    className: `legend-row${picked === p.name ? " on" : ""}`,
    key: p.name,
    onClick: () => onPick(picked === p.name ? "" : p.name),
    title: picked === p.name ? "Show every protocol" : `Show only ${p.name} packets`
  }, React.createElement("span", {
    className: `swatch c-${protoClass(p.name)}`
  }), React.createElement("span", null, p.name), React.createElement("span", {
    className: "count"
  }, p.packets.toLocaleString(), " pkts \xB7 ", formatBytes(p.bytes)), React.createElement("span", {
    className: "pct"
  }, p.percent, "%"))), !list.length && React.createElement("div", {
    className: "muted"
  }, "No packets yet.")));
}
function TopApps({
  apps,
  retention,
  enabled,
  onPick,
  picked
}) {
  const list = apps || [];
  const max = Math.max(1, ...list.map(a => a.bytes));
  return React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", {
    className: "label"
  }, "Top applications"), React.createElement("div", {
    className: "muted"
  }, "programs on this computer", retention ? `, last ${formatRetention(retention)}` : "")), React.createElement("div", {
    className: "hosts"
  }, list.map(a => React.createElement("button", {
    className: `host app-row${picked === a.app ? " on" : ""}`,
    key: a.app,
    onClick: () => onPick(picked === a.app ? "" : a.app),
    title: picked === a.app ? "Show every program" : `${a.packets.toLocaleString()} packets. Click to show only ${a.app}.`
  }, React.createElement("span", {
    className: "name"
  }, a.app), React.createElement("span", {
    className: "bar"
  }, React.createElement("div", {
    style: {
      width: `${100 * a.bytes / max}%`
    }
  })), React.createElement("span", {
    className: "size"
  }, formatBytes(a.bytes)))), !list.length && React.createElement("div", {
    className: "muted"
  }, enabled === false ? "Shown during live capture. A replayed file does not say which program sent each packet." : "No programs named yet.")));
}
function TopHosts({
  hosts,
  retention,
  onPick
}) {
  const list = hosts || [];
  const max = Math.max(1, ...list.map(h => h.bytes));
  return React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", {
    className: "label"
  }, "Top hosts"), React.createElement("div", {
    className: "muted"
  }, "bytes sent + received", retention ? `, last ${formatRetention(retention)}` : "")), React.createElement("div", {
    className: "hosts"
  }, list.map(h => React.createElement("button", {
    className: "host",
    key: h.host,
    onClick: () => onPick(h.host),
    title: `${h.packets.toLocaleString()} packets. Click to show only this host.`
  }, React.createElement("span", {
    className: "name"
  }, h.host, h.name && React.createElement("small", null, h.name)), React.createElement("span", {
    className: "bar"
  }, React.createElement("div", {
    style: {
      width: `${100 * h.bytes / max}%`
    }
  })), React.createElement("span", {
    className: "size"
  }, formatBytes(h.bytes)))), !list.length && React.createElement("div", {
    className: "muted"
  }, "No hosts yet.")));
}
function readSetting(key, fallback) {
  try {
    const value = window.localStorage.getItem(key);
    return value === null ? fallback : JSON.parse(value);
  } catch (err) {
    return fallback;
  }
}
function useSetting(key, fallback) {
  const [value, setValue] = useState(() => readSetting(key, fallback));
  useEffect(() => {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (err) {}
  }, [key, value]);
  return [value, setValue];
}
function useFetch(url, everyMs) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    let stopped = false;
    async function load() {
      try {
        const body = await getJSON(url);
        if (!stopped) {
          setData(body);
          setError(null);
        }
      } catch (err) {
        if (err.status === 401) window.location.reload();else if (!stopped) setError(err.message);
      }
    }
    load();
    const timer = everyMs ? setInterval(load, everyMs) : null;
    return () => {
      stopped = true;
      if (timer) clearInterval(timer);
    };
  }, [url, everyMs]);
  return {
    data,
    error
  };
}
const APP_LAYER = /^(DNS|DHCP|HTTP|TLS)\b/;
function HexView({
  packetId
}) {
  const {
    data,
    error
  } = useFetch(`/api/packets/${packetId}/bytes`, 0);
  if (error) return React.createElement("div", {
    className: "muted"
  }, error);
  if (!data) return React.createElement("div", {
    className: "muted"
  }, "Loading bytes\u2026");
  const bytes = data.hex.match(/../g) || [];
  const layerOf = i => data.layers.findIndex(l => i >= l.start && i < l.end);
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 16) rows.push(offset);
  return React.createElement("div", {
    className: "hexview"
  }, React.createElement("div", {
    className: "hex-legend"
  }, data.layers.map((l, i) => React.createElement("span", {
    key: i,
    className: `hx l${i % 6}`
  }, l.name, " ", React.createElement("small", null, l.end - l.start, " B")))), React.createElement("div", {
    className: "hex-rows",
    role: "table",
    "aria-label": "Packet bytes"
  }, rows.map(offset => React.createElement("div", {
    className: "hex-row",
    role: "row",
    key: offset
  }, React.createElement("span", {
    className: "off"
  }, offset.toString(16).padStart(4, "0")), React.createElement("span", {
    className: "bytes"
  }, bytes.slice(offset, offset + 16).map((b, j) => React.createElement("span", {
    key: j,
    className: `hx l${layerOf(offset + j) % 6}`
  }, b))), React.createElement("span", {
    className: "ascii"
  }, bytes.slice(offset, offset + 16).map((b, j) => {
    const code = parseInt(b, 16);
    return React.createElement("span", {
      key: j,
      className: `hx l${layerOf(offset + j) % 6}`
    }, code > 31 && code < 127 ? String.fromCharCode(code) : ".");
  }))))));
}
function PacketDetails({
  packet
}) {
  const [showBytes, setShowBytes] = useState(false);
  useEffect(() => setShowBytes(false), [packet?.id]);
  return React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", {
    className: "label"
  }, "Packet details"), packet && React.createElement("div", {
    className: "head-buttons"
  }, React.createElement("span", {
    className: "muted"
  }, "#", packet.id), React.createElement("button", {
    onClick: () => setShowBytes(s => !s),
    "aria-expanded": showBytes
  }, showBytes ? "Hide bytes" : "Show bytes"))), !packet && React.createElement("div", {
    className: "muted"
  }, "Click a packet to see its headers decoded layer by layer."), packet && React.createElement("div", null, packet.app && React.createElement("div", {
    className: "layer l-app"
  }, React.createElement("div", {
    className: "name"
  }, "PROGRAM"), React.createElement("div", {
    className: "body"
  }, packet.app, React.createElement("br", null), React.createElement("span", null, "sent or received by this program on this computer"))), APP_LAYER.test(packet.info) && React.createElement("div", {
    className: "layer l-application"
  }, React.createElement("div", {
    className: "name"
  }, packet.info.split(" ")[0]), React.createElement("div", {
    className: "body"
  }, packet.info.split(" ").slice(1).join(" "))), packet.src_mac && React.createElement("div", {
    className: "layer l-link"
  }, React.createElement("div", {
    className: "name"
  }, "ETHERNET"), React.createElement("div", {
    className: "body"
  }, React.createElement("span", null, "src"), " ", packet.src_mac, React.createElement("br", null), React.createElement("span", null, "dst"), " ", packet.dst_mac)), packet.proto === "ARP" ? React.createElement("div", {
    className: "layer l-net"
  }, React.createElement("div", {
    className: "name"
  }, "ARP"), React.createElement("div", {
    className: "body"
  }, packet.info)) : packet.ip_version && React.createElement("div", {
    className: "layer l-net"
  }, React.createElement("div", {
    className: "name"
  }, "IPv", packet.ip_version), React.createElement("div", {
    className: "body"
  }, React.createElement("span", null, "src"), " ", packet.src, packet.src_name ? ` (${packet.src_name})` : "", React.createElement("br", null), React.createElement("span", null, "dst"), " ", packet.dst, packet.dst_name ? ` (${packet.dst_name})` : "", React.createElement("br", null), React.createElement("span", null, packet.ip_version === 6 ? "hop limit" : "ttl"), " ", packet.ttl)), ["TCP", "UDP", "ICMP"].includes(packet.proto) && React.createElement("div", {
    className: "layer l-trans"
  }, React.createElement("div", {
    className: "name"
  }, packet.proto), React.createElement("div", {
    className: "body"
  }, packet.sport != null && React.createElement(React.Fragment, null, React.createElement("span", null, "ports"), " ", packet.sport, " \u2192 ", packet.dport, React.createElement("br", null)), packet.flags.length > 0 && React.createElement(React.Fragment, null, React.createElement("span", null, "flags"), " ", packet.flags.join(", "), React.createElement("br", null)), packet.seq != null && React.createElement(React.Fragment, null, React.createElement("span", null, "seq"), " ", packet.seq, " ", React.createElement("span", null, "ack"), " ", packet.ack, React.createElement("br", null)), packet.payload_len > 0 && React.createElement(React.Fragment, null, React.createElement("span", null, "data"), " ", packet.payload_len, " bytes", React.createElement("br", null)), packet.tcp_note && React.createElement(React.Fragment, null, React.createElement("span", null, "note"), " ", React.createElement("b", {
    className: "note"
  }, packet.tcp_note), React.createElement("br", null)), packet.service && React.createElement(React.Fragment, null, React.createElement("span", null, "service"), " ", packet.service, React.createElement("br", null)), packet.proto === "ICMP" && React.createElement(React.Fragment, null, React.createElement("span", null, "type"), " ", packet.info))), React.createElement("div", {
    className: "layer l-data"
  }, React.createElement("div", {
    className: "name"
  }, "FRAME"), React.createElement("div", {
    className: "body"
  }, React.createElement("span", null, "size"), " ", packet.length, " bytes", React.createElement("br", null), React.createElement("span", null, "time"), " ", formatTime(packet.time))), showBytes && React.createElement(HexView, {
    packetId: packet.id
  })));
}
function ViewTabs({
  view,
  setView
}) {
  const views = [["packets", "Packets"], ["connections", "Connections"], ["devices", "Devices"], ["history", "History"]];
  return React.createElement("div", {
    className: "view-tabs",
    role: "tablist",
    "aria-label": "Views"
  }, views.map(([key, text]) => React.createElement("button", {
    key: key,
    role: "tab",
    "aria-selected": view === key,
    className: view === key ? "on" : "",
    onClick: () => setView(key)
  }, text)));
}
function Tiles({
  items
}) {
  return React.createElement("div", {
    className: "summary"
  }, items.map(item => React.createElement("div", {
    className: "metric",
    key: item.label
  }, React.createElement("div", {
    className: "label"
  }, item.label), React.createElement("div", {
    className: "value"
  }, item.value), React.createElement("div", {
    className: "sub"
  }, item.sub))));
}
const STATE_CLASS = {
  established: "good",
  "SYN sent": "wait",
  "SYN received": "wait",
  closing: "wait",
  closed: "done",
  reset: "bad",
  active: "good",
  "joined late": "done"
};
function ConnectionsView({
  onFocus
}) {
  const {
    data
  } = useFetch("/api/connections?limit=500", 2000);
  const [query, setQuery] = useState("");
  const all = data?.connections || [];
  const q = query.trim().toLowerCase();
  const rows = q ? all.filter(c => [c.client, c.server, c.server_name, c.app, c.state, c.proto, c.service].some(v => v && String(v).toLowerCase().includes(q))) : all;
  const s = data?.summary || {};
  return React.createElement(React.Fragment, null, React.createElement(Tiles, {
    items: [{
      label: "Connections",
      value: (s.connections ?? 0).toLocaleString(),
      sub: `${s.tcp ?? 0} TCP · ${s.udp ?? 0} UDP`
    }, {
      label: "Average round trip",
      value: s.avg_rtt_ms != null ? `${s.avg_rtt_ms} ms` : "-",
      sub: "SYN to SYN-ACK"
    }, {
      label: "Retransmissions",
      value: `${s.retransmission_percent ?? 0}%`,
      sub: "of TCP packets sent again"
    }, {
      label: "Duplicate ACKs",
      value: (s.dup_acks ?? 0).toLocaleString(),
      sub: "receivers asking for lost data"
    }]
  }), React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", null, React.createElement("div", {
    className: "label"
  }, "Connections"), React.createElement("div", {
    className: "muted"
  }, "Newest activity first \xB7 click one to see its packets")), React.createElement("input", {
    className: "search",
    placeholder: "Search connections",
    value: query,
    onChange: e => setQuery(e.target.value),
    "aria-label": "Search connections"
  })), React.createElement("div", {
    className: "table-wrap tall"
  }, React.createElement("table", null, React.createElement("thead", null, React.createElement("tr", null, React.createElement("th", null, "LAST SEEN"), React.createElement("th", null, "APP"), React.createElement("th", null, "CLIENT"), React.createElement("th", null, "SERVER"), React.createElement("th", null, "PROTO"), React.createElement("th", null, "STATE"), React.createElement("th", {
    className: "num"
  }, "ROUND TRIP"), React.createElement("th", {
    className: "num"
  }, "SENT"), React.createElement("th", {
    className: "num"
  }, "RECEIVED"), React.createElement("th", {
    className: "num"
  }, "RETRANS."), React.createElement("th", {
    className: "num"
  }, "DURATION"))), React.createElement("tbody", null, rows.map(c => React.createElement("tr", {
    key: c.id,
    onClick: () => onFocus(c.server),
    title: "Show this connection's packets"
  }, React.createElement("td", {
    className: "time"
  }, formatTime(c.last_seen)), React.createElement("td", {
    className: "program"
  }, c.app || React.createElement("span", {
    className: "none"
  }, "\u2014")), React.createElement("td", null, withPort(c.client, c.client_port)), React.createElement("td", null, withPort(c.server, c.server_port), c.server_name && React.createElement("span", {
    className: "hostname"
  }, c.server_name)), React.createElement("td", null, React.createElement("span", {
    className: `badge p-${protoClass(c.proto)}`
  }, c.proto)), React.createElement("td", null, React.createElement("span", {
    className: `state ${STATE_CLASS[c.state] || ""}`
  }, c.state)), React.createElement("td", {
    className: "num"
  }, c.rtt_ms != null ? `${c.rtt_ms} ms` : "-"), React.createElement("td", {
    className: "num"
  }, formatBytes(c.bytes_out)), React.createElement("td", {
    className: "num"
  }, formatBytes(c.bytes_in)), React.createElement("td", {
    className: "num"
  }, c.retransmissions || ""), React.createElement("td", {
    className: "num"
  }, formatDuration(c.duration)))))), !rows.length && React.createElement("div", {
    className: "empty"
  }, q ? "No connections match." : "No connections yet."))));
}
function DevicesView({
  onFocus
}) {
  const {
    data
  } = useFetch("/api/devices", 3000);
  const devices = data?.devices || [];
  return React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", null, React.createElement("div", {
    className: "label"
  }, "Devices on this network"), React.createElement("div", {
    className: "muted"
  }, "Seen in their own traffic \xB7 maker from the MAC address \xB7 name from DHCP")), React.createElement("span", {
    className: "muted"
  }, devices.length, " found")), React.createElement("div", {
    className: "devices"
  }, devices.map(d => React.createElement("button", {
    className: "device",
    key: d.mac,
    onClick: () => onFocus(d.mac),
    title: "Show this device's packets"
  }, React.createElement("span", {
    className: "device-name"
  }, d.name || d.maker || "Unknown device", d.is_this_computer && React.createElement("span", {
    className: "tag"
  }, "THIS COMPUTER"), d.is_router && React.createElement("span", {
    className: "tag"
  }, "ROUTER")), React.createElement("span", {
    className: "muted"
  }, d.name ? d.maker || "unknown maker" : ""), React.createElement("span", {
    className: "mono"
  }, d.addresses.join(", ") || "no address seen"), React.createElement("span", {
    className: "mono muted"
  }, d.mac), React.createElement("span", {
    className: "muted"
  }, d.packets.toLocaleString(), " packets \xB7 ", formatBytes(d.bytes), " \xB7 last ", formatTime(d.last_seen)))), !devices.length && React.createElement("div", {
    className: "muted"
  }, "No devices seen yet.")));
}
function HistoryView() {
  const [hours, setHours] = useState(24);
  const {
    data,
    error
  } = useFetch(`/api/history?hours=${hours}`, 10000);
  if (data && !data.enabled) {
    return React.createElement("div", {
      className: "card"
    }, React.createElement("div", {
      className: "muted"
    }, "History is off. Start without --no-history to keep it."));
  }
  const maxServer = Math.max(1, ...(data?.top_servers || []).map(s => s.bytes_in + s.bytes_out));
  return React.createElement(React.Fragment, null, React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", null, React.createElement("div", {
    className: "label"
  }, "History"), React.createElement("div", {
    className: "muted"
  }, "Kept between runs for ", data?.keep_days ?? 7, " days", data?.path ? ` in ${data.path}` : "", error ? ` · ${error}` : "", data?.error ? ` · ${data.error}` : "")), React.createElement("div", {
    className: "seg small",
    role: "group",
    "aria-label": "Time range"
  }, [[1, "1 hour"], [6, "6 hours"], [24, "24 hours"], [168, "7 days"]].map(([h, text]) => React.createElement("button", {
    key: h,
    className: hours === h ? "on" : "",
    "aria-pressed": hours === h,
    onClick: () => setHours(h)
  }, text)))), React.createElement("div", {
    className: "history-grid"
  }, React.createElement("div", null, React.createElement("div", {
    className: "label sub-label"
  }, "Sessions"), (data?.sessions || []).map(s => React.createElement("div", {
    className: "history-row",
    key: s.id
  }, React.createElement("span", null, s.mode === "replay" ? "Replay" : "Live", " \xB7 ", String(s.source).split(/[\\/]/).pop()), React.createElement("span", {
    className: "muted"
  }, formatTime(s.started), " \u2013 ", formatTime(s.ended), " \xB7 ", (s.packets || 0).toLocaleString(), " packets \xB7 ", formatBytes(s.bytes)))), !data?.sessions?.length && React.createElement("div", {
    className: "muted"
  }, "No sessions in this time.")), React.createElement("div", null, React.createElement("div", {
    className: "label sub-label"
  }, "Busiest servers"), (data?.top_servers || []).map(s => React.createElement("div", {
    className: "host",
    key: s.server
  }, React.createElement("span", {
    className: "name"
  }, s.server, s.name && React.createElement("small", null, s.name)), React.createElement("span", {
    className: "bar"
  }, React.createElement("div", {
    style: {
      width: `${100 * (s.bytes_in + s.bytes_out) / maxServer}%`
    }
  })), React.createElement("span", {
    className: "size"
  }, formatBytes(s.bytes_in + s.bytes_out)))), !data?.top_servers?.length && React.createElement("div", {
    className: "muted"
  }, "No connections in this time.")))), React.createElement("div", {
    className: "card"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", {
    className: "label"
  }, "Alerts in this time")), React.createElement("div", {
    className: "table-wrap"
  }, React.createElement("table", null, React.createElement("thead", null, React.createElement("tr", null, React.createElement("th", null, "LAST SEEN"), React.createElement("th", null, "SEVERITY"), React.createElement("th", null, "ALERT"), React.createElement("th", {
    className: "num"
  }, "TIMES"))), React.createElement("tbody", null, (data?.alerts || []).map((a, i) => React.createElement("tr", {
    key: `${a.session}-${i}`
  }, React.createElement("td", {
    className: "time"
  }, formatTime(a.last_seen)), React.createElement("td", null, React.createElement("span", {
    className: `sev s-${a.severity}`
  }, SEVERITY_LABEL[a.severity])), React.createElement("td", {
    className: "wrap"
  }, React.createElement("b", null, a.title), React.createElement("span", {
    className: "hostname"
  }, a.detail)), React.createElement("td", {
    className: "num"
  }, a.count.toLocaleString()))))), !data?.alerts?.length && React.createElement("div", {
    className: "empty"
  }, "No alerts in this time."))));
}
function SettingsPanel({
  onClose,
  refresh
}) {
  const {
    data
  } = useFetch("/api/interfaces", 0);
  const [iface, setIface] = useState(null);
  const [filter, setFilter] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const chosen = iface ?? data?.current ?? "";
  const bpf = filter ?? data?.filter ?? "";
  const live = data?.mode === "live";
  async function apply() {
    setBusy(true);
    const result = await postJSON("/api/capture/start", {
      iface: chosen,
      filter: bpf
    });
    setBusy(false);
    setMessage({
      ok: result.ok,
      text: result.ok ? "Capture restarted with these settings." : result.message
    });
    if (result.ok) refresh();
  }
  return React.createElement("div", {
    className: "popover",
    role: "dialog",
    "aria-label": "Capture settings"
  }, React.createElement("div", {
    className: "card-head"
  }, React.createElement("div", {
    className: "label"
  }, "Capture settings"), React.createElement("button", {
    className: "link",
    onClick: onClose
  }, "Close")), !live && data && React.createElement("p", {
    className: "muted"
  }, "Replaying a file: interface and filter apply to live capture only."), React.createElement("label", {
    className: "field-label",
    htmlFor: "iface"
  }, "Interface"), React.createElement("select", {
    id: "iface",
    value: chosen,
    disabled: !live,
    onChange: e => setIface(e.target.value)
  }, (data?.interfaces || []).map(i => React.createElement("option", {
    key: i.name,
    value: i.name
  }, i.name, i.ips.length ? ` (${i.ips[0]})` : "", i.default ? " · default" : ""))), React.createElement("label", {
    className: "field-label",
    htmlFor: "bpf"
  }, "Capture filter (BPF)"), React.createElement("input", {
    id: "bpf",
    className: "mono-input",
    value: bpf,
    disabled: !live,
    placeholder: "e.g. tcp port 443, or host 192.168.1.5",
    onChange: e => setFilter(e.target.value)
  }), React.createElement("p", {
    className: "muted"
  }, "Only matching packets are captured at all. Leave empty to capture everything."), message && React.createElement("div", {
    className: `fix-message ${message.ok ? "good" : "bad"}`
  }, message.text), React.createElement("button", {
    className: "primary",
    disabled: !live || busy,
    onClick: apply
  }, busy ? "Restarting…" : "Apply and restart capture"));
}
const THEMES = ["auto", "light", "dark"];
function useAppearance() {
  const [theme, setTheme] = useSetting("sniffer.theme", "auto");
  const [large, setLarge] = useSetting("sniffer.large", false);
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "auto") delete root.dataset.theme;else root.dataset.theme = theme;
    if (large) root.dataset.size = "large";else delete root.dataset.size;
  }, [theme, large]);
  return {
    theme,
    cycleTheme: () => setTheme(t => THEMES[(THEMES.indexOf(t) + 1) % THEMES.length]),
    large,
    setLarge
  };
}
function useAlertNotifications(security, enabled) {
  const seen = useRef(null);
  useEffect(() => {
    const high = (security?.alerts || []).filter(a => a.severity === "high");
    if (seen.current === null) {
      if (security) seen.current = new Set(high.map(a => a.id));
      return;
    }
    const fresh = high.filter(a => !seen.current.has(a.id));
    fresh.forEach(a => seen.current.add(a.id));
    if (!enabled || !fresh.length) return;
    try {
      const audio = new (window.AudioContext || window.webkitAudioContext)();
      const tone = audio.createOscillator();
      const gain = audio.createGain();
      tone.frequency.value = 880;
      gain.gain.setValueAtTime(0.15, audio.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audio.currentTime + 0.4);
      tone.connect(gain).connect(audio.destination);
      tone.start();
      tone.stop(audio.currentTime + 0.4);
    } catch (err) {}
    if ("Notification" in window && Notification.permission === "granted") {
      fresh.forEach(a => new Notification(`Security alert: ${a.title}`, {
        body: a.detail,
        tag: `alert-${a.id}`
      }));
    }
  }, [security, enabled]);
}
function TopbarTools({
  capture,
  refresh,
  notify,
  setNotify
}) {
  const {
    theme,
    cycleTheme,
    large,
    setLarge
  } = useAppearance();
  const [settings, setSettings] = useState(false);
  async function toggleNotify() {
    if (!notify && "Notification" in window && Notification.permission === "default") {
      try {
        await Notification.requestPermission();
      } catch (err) {}
    }
    setNotify(!notify);
  }
  return React.createElement("div", {
    className: "tools"
  }, React.createElement("button", {
    className: "tool",
    onClick: () => setSettings(s => !s),
    "aria-expanded": settings,
    title: "Interface and capture filter"
  }, "Settings"), React.createElement("button", {
    className: "tool",
    onClick: toggleNotify,
    "aria-pressed": notify,
    title: notify ? "Pop-up and sound for high-severity alerts: on" : "Pop-up and sound for high-severity alerts: off"
  }, "Alerts: ", notify ? "on" : "off"), React.createElement("button", {
    className: "tool",
    onClick: cycleTheme,
    title: "Light, dark, or follow the computer"
  }, "Theme: ", theme), React.createElement("button", {
    className: "tool",
    onClick: () => setLarge(!large),
    "aria-pressed": large,
    title: "Larger text, for projectors"
  }, large ? "Normal text" : "Large text"), React.createElement("a", {
    className: "tool",
    href: "/report",
    target: "_blank",
    rel: "noopener"
  }, "Report"), settings && React.createElement(SettingsPanel, {
    onClose: () => setSettings(false),
    refresh: refresh,
    capture: capture
  }));
}
function App() {
  const [filters, setFilters] = useState(NO_FILTERS);
  const {
    packets,
    stats,
    security,
    offline,
    paused,
    setPaused,
    filterError,
    refresh
  } = usePolling(filters);
  const [selected, setSelected] = useState(null);
  const [view, setView] = useSetting("sniffer.view", "packets");
  const [notify, setNotify] = useSetting("sniffer.notify", false);
  useAlertNotifications(security, notify);
  const capture = stats?.capture;
  const retention = stats?.retention;
  function focusHost(host) {
    if (!host) return;
    setFilters({
      ...NO_FILTERS,
      host
    });
    setView("packets");
    setTimeout(() => {
      const table = document.getElementById("packets");
      if (table && table.getBoundingClientRect().top < 0) table.scrollIntoView({
        behavior: "smooth"
      });
    }, 0);
  }
  return React.createElement(React.Fragment, null, React.createElement("header", {
    className: "topbar"
  }, React.createElement("div", {
    className: "topbar-inner"
  }, React.createElement("div", {
    className: "brand"
  }, React.createElement("div", {
    className: "layers"
  }, React.createElement("span", null, "ETH"), React.createElement("span", null, "IP"), React.createElement("span", null, "TCP/UDP")), React.createElement("h1", null, "Packet Sniffer Dashboard")), React.createElement("div", {
    className: "topbar-right"
  }, React.createElement(StatusPill, {
    capture: capture,
    offline: offline
  }), !offline && React.createElement(CaptureButton, {
    capture: capture,
    refresh: refresh
  }))), React.createElement("div", {
    className: "topbar-inner tools-row"
  }, React.createElement(ViewTabs, {
    view: view,
    setView: setView
  }), React.createElement(TopbarTools, {
    capture: capture,
    refresh: refresh,
    notify: notify,
    setNotify: setNotify
  }))), React.createElement("div", {
    className: "app"
  }, React.createElement(Banners, {
    capture: capture,
    security: security,
    onFocus: focusHost
  }), view === "packets" && React.createElement(React.Fragment, null, React.createElement(Summary, {
    stats: stats
  }), React.createElement(BandwidthChart, {
    points: stats?.bandwidth,
    apps: stats?.app_bandwidth,
    appsEnabled: capture?.apps
  }), React.createElement("div", {
    className: "grid"
  }, React.createElement(PacketTable, {
    packets: packets,
    paused: paused,
    setPaused: setPaused,
    selectedId: selected?.id,
    onSelect: setSelected,
    filters: filters,
    setFilters: setFilters,
    filterError: filterError,
    retention: retention,
    capturing: capture?.running ?? true
  }), React.createElement("div", {
    className: "side"
  }, React.createElement(PacketDetails, {
    packet: selected
  }), React.createElement(SecurityPanel, {
    security: security,
    onFocus: focusHost,
    refresh: refresh
  }), React.createElement(Protocols, {
    protocols: stats?.protocols,
    retention: retention,
    picked: filters.proto,
    onPick: proto => setFilters(f => ({
      ...f,
      proto
    }))
  }), React.createElement(TopApps, {
    apps: stats?.top_apps,
    retention: retention,
    enabled: capture?.apps,
    picked: filters.q,
    onPick: app => setFilters({
      ...NO_FILTERS,
      q: app
    })
  }), React.createElement(TopHosts, {
    hosts: stats?.top_hosts,
    retention: retention,
    onPick: focusHost
  })))), view === "connections" && React.createElement(ConnectionsView, {
    onFocus: focusHost
  }), view === "devices" && React.createElement(DevicesView, {
    onFocus: focusHost
  }), view === "history" && React.createElement(HistoryView, null), React.createElement("footer", {
    className: "footer"
  }, "Packet Sniffer ", stats?.version || "", " \xB7 team Big Packet \xB7 capture only on your own device and network")));
}
ReactDOM.createRoot(document.getElementById("root")).render(React.createElement(App, null));
