// Packet Sniffer Dashboard: polls the Flask API once a second and redraws.
const { useEffect, useLayoutEffect, useRef, useState } = React;

const POLL_MS = 1000;
const KEEP_ROWS = 300;   // packets kept in the browser
const SHOW_ROWS = 150;   // packets drawn in the table
const PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "Other"];
const NO_FILTERS = { proto: "", host: "", port: "", q: "" };
const SEVERITY_LABEL = { high: "HIGH", medium: "MEDIUM", low: "LOW" };

function formatBytes(n) {
  if (n == null) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function formatTime(epochSeconds) {
  // 12-hour clock with a two-digit hour, so times line up in the table: 04:38:14 PM
  return new Date(epochSeconds * 1000).toLocaleTimeString("en-US", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true,
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
  const response = await fetch(url, { cache: "no-store" });
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

  // A new filter starts the table over with the matching packets the server still holds.
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
      if (stopped || asked !== queryRef.current) return;   // the filter changed meanwhile
      reload.current = false;
      setFilterError(null);
      lastId.current = p.last_id;
      // Rows older than the server's retention period decay here too.
      const cutoff = retention.current ? Date.now() / 1000 - retention.current : -Infinity;
      setPackets(prev => [...p.packets.reverse(), ...prev].filter(r => r.time >= cutoff).slice(0, KEEP_ROWS));
    }

    async function tick() {
      if (busy) return;
      busy = true;
      try {
        const [s, a] = await Promise.all([getJSON("/api/stats"), getJSON("/api/alerts")]);
        retention.current = s.retention;
        // The server restarted and its packet ids began again from 1.
        if (s.last_id < lastId.current) {
          lastId.current = 0;
          setPackets([]);
        }
        if (!pausedRef.current || reload.current) await fetchPackets();
        if (!stopped) { setStats(s); setSecurity(a); setOffline(false); }
      } catch (err) {
        // The access code changed (sniffer.py restarted): show the unlock page.
        if (err.status === 401) window.location.reload();
        else if (!stopped) setOffline(true);
      } finally {
        busy = false;
      }
    }

    tickRef.current = tick;
    tick();
    const timer = setInterval(tick, POLL_MS);
    return () => { stopped = true; clearInterval(timer); };
  }, []);

  const refresh = () => tickRef.current?.();
  return { packets, stats, security, offline, paused, setPaused, filterError, refresh };
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

function StatusPill({ capture, offline }) {
  if (offline) {
    return <div className="status error"><span className="dot" /><b>OFFLINE</b> sniffer.py is not running</div>;
  }
  if (!capture) return <div className="status"><span className="dot" />Connecting&hellip;</div>;
  if (capture.error) {
    return <div className="status error"><span className="dot" /><b>STOPPED</b> {capture.source}</div>;
  }
  if (capture.stopped && !capture.running) {
    return <div className="status"><span className="dot" /><b>STOPPED</b> {capture.stopped}</div>;
  }
  if (capture.mode === "replay") {
    const file = (capture.source || "").split(/[\\/]/).pop();
    return (
      <div className="status replay">
        <span className="dot" /><b>{capture.running ? "REPLAY" : "REPLAY DONE"}</b> {file}
      </div>
    );
  }
  return (
    <div className="status live">
      <span className="dot" /><b>LIVE</b> Capturing on {capture.source}
      {capture.filter ? ` · filter: ${capture.filter}` : ""}
    </div>
  );
}

function Banners({ capture, security, onFocus }) {
  const high = (security?.alerts || []).filter(a => a.severity === "high");
  const saving = capture?.saving;
  return (
    <>
      {high.length > 0 && (
        <div className="banner danger">
          <span className="tag">SECURITY</span>
          <span>
            {high.length} high-severity alert{high.length > 1 ? "s" : ""}. Latest:{" "}
            <button className="link" onClick={() => onFocus(high[0].focus)}>{high[0].title}</button>
          </span>
        </div>
      )}
      {capture?.error && (
        <div className="banner error"><span className="tag">CAPTURE</span><span>{capture.error}</span></div>
      )}
      {capture?.stopped && !capture.running && !capture.error && (
        <div className="banner info">
          <span className="tag">STOPPED</span>
          <span>
            Capture stopped by itself ({capture.stopped}) after {capture.captured.toLocaleString()} packets.
            Run sniffer.py again to capture more.
          </span>
        </div>
      )}
      {capture?.mode === "replay" && !capture.error && !capture.stopped && (
        <div className="banner info">
          <span className="tag">REPLAY</span>
          <span>Showing packets from a saved capture file, not live traffic. Run without --pcap to capture live.</span>
        </div>
      )}
      {saving && (
        <div className={`banner ${saving.error ? "error" : "saved"}`}>
          <span className="tag">SAVING</span>
          <span>
            {saving.error || <>
              Packets are saved in <code>{saving.folder}</code>: {saving.files} file{saving.files === 1 ? "" : "s"},{" "}
              {formatBytes(saving.bytes)}. A new file starts every {saving.max_mb} MB and only the newest{" "}
              {saving.keep_files} are kept{saving.deleted ? ` (${saving.deleted} older deleted)` : ""}.
            </>}
          </span>
        </div>
      )}
    </>
  );
}

function Summary({ stats }) {
  const s = stats || {};
  const items = [
    { label: "Packets captured", value: (s.total_packets ?? 0).toLocaleString(), sub: `in ${formatDuration(s.uptime)}` },
    { label: "Data captured", value: formatBytes(s.total_bytes ?? 0), sub: "on the wire, all layers" },
    { label: "Speed now", value: `${formatBytes(s.bytes_per_sec ?? 0)}/s`, sub: "during the last full second" },
    { label: "Packets / sec", value: (s.packets_per_sec ?? 0).toLocaleString(), sub: s.capture?.dropped ? `${s.capture.dropped} dropped` : "none dropped" },
  ];
  return (
    <div className="summary">
      {items.map(item => (
        <div className="metric" key={item.label}>
          <div className="label">{item.label}</div>
          <div className="value">{item.value}</div>
          <div className="sub">{item.sub}</div>
        </div>
      ))}
    </div>
  );
}

// Round the top of the y-axis up to 1, 2 or 5 x 10^n in a readable unit (at least 1 KB/s).
function bandwidthScale(maxBytes) {
  maxBytes = Math.max(maxBytes, 1024);
  const units = [["B", 1], ["KB", 1024], ["MB", 1024 ** 2], ["GB", 1024 ** 3]];
  let [unit, size] = units[0];
  for (const u of units) if (maxBytes >= u[1]) [unit, size] = u;
  const value = Math.max(maxBytes / size, 1);
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const top = [1, 2, 5, 10].map(m => m * magnitude).find(v => v >= value);
  const label = v => (v === 0 ? "0" : `${+v.toFixed(1)} ${unit}/s`);
  return { top: top * size, ticks: [0, top / 2, top].map(v => ({ value: v * size, label: label(v) })) };
}

// Labels at the right end of each line, nudged apart so they never overlap.
function spreadLabels(items, minGap, top, bottom) {
  const sorted = [...items].sort((a, b) => a.y - b.y);
  for (let i = 1; i < sorted.length; i++) sorted[i].y = Math.max(sorted[i].y, sorted[i - 1].y + minGap);
  const overflow = sorted.length ? sorted[sorted.length - 1].y - bottom : 0;
  if (overflow > 0) sorted.forEach(s => { s.y = Math.max(top, s.y - overflow); });
  return sorted;
}

function BandwidthChart({ points, apps, appsEnabled }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState(null);
  const [mode, setMode] = useState("total");
  const byProgram = mode === "programs";
  // The newest second is still filling up, so the graph ends at the last full one.
  const totals = (points || []).slice(0, -1);
  const appPoints = (apps?.points || []).slice(0, -1);
  const series = byProgram
    ? (apps?.apps || []).map((app, i) => ({ key: app, label: app, cls: `s${i + 1}`, values: appPoints.map(p => p.bytes[app] || 0) }))
    : [{ key: "total", label: "All traffic", cls: "s-total", values: totals.map(d => d.bytes) }];
  const times = byProgram ? appPoints.map(p => p.t) : totals.map(d => d.t);
  const n = times.length;
  const H = 180;
  const M = { top: 12, right: byProgram ? 132 : 14, bottom: 26, left: 70 };
  const innerW = Math.max(0, width - M.left - M.right);
  const innerH = H - M.top - M.bottom;
  const peak = Math.max(0, ...series.flatMap(s => s.values));
  const scale = bandwidthScale(peak);
  const x = i => M.left + (n > 1 ? (i / (n - 1)) * innerW : 0);
  const y = v => M.top + innerH - (v / scale.top) * innerH;
  const path = values => values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const marks = [0, 15, 30, 45].map(ago => n - 1 - ago).filter(i => i >= 0);
  const h = hover != null && hover < n ? hover : null;
  const labels = byProgram && n
    ? spreadLabels(series.map(s => ({ key: s.key, label: s.label, cls: s.cls, y: y(s.values[n - 1]) })), 13, M.top, M.top + innerH)
    : [];

  function onPointer(e) {
    if (!n || !innerW) return;
    const px = e.clientX - e.currentTarget.getBoundingClientRect().left;
    const i = Math.round(((px - M.left) / innerW) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  }
  function onKey(e) {
    if (!n) return;
    if (e.key === "ArrowLeft") setHover(i => Math.max(0, (i ?? n) - 1));
    else if (e.key === "ArrowRight") setHover(i => Math.min(n - 1, (i ?? -1) + 1));
    else if (e.key === "Escape") setHover(null);
    else return;
    e.preventDefault();
  }

  const empty = byProgram
    ? (appsEnabled === false ? "Programs are named during live capture only" : "No program traffic in the last minute")
    : "No traffic in the last minute";

  return (
    <div className="card chart-card">
      <div className="card-head">
        <div>
          <div className="label">Bandwidth</div>
          <div className="muted">Bytes per second over the last minute{byProgram ? ", busiest programs" : ""}</div>
        </div>
        <div className="chart-head-right">
          <span className="muted">peak {formatBytes(peak)}/s</span>
          <div className="seg small" role="group" aria-label="What to show">
            {[["total", "Total"], ["programs", "By program"]].map(([key, text]) => (
              <button key={key} className={mode === key ? "on" : ""} aria-pressed={mode === key}
                onClick={() => { setMode(key); setHover(null); }}>{text}</button>
            ))}
          </div>
        </div>
      </div>
      <div
        className="chart"
        ref={ref}
        tabIndex={0}
        aria-label="Bandwidth over the last minute. Use the arrow keys to read each second."
        onPointerMove={onPointer}
        onPointerLeave={() => setHover(null)}
        onFocus={() => setHover(i => i ?? n - 1)}
        onBlur={() => setHover(null)}
        onKeyDown={onKey}
      >
        {width > 0 && (
          <svg width={width} height={H} aria-hidden="true">
            {scale.ticks.map(t => (
              <g key={t.value}>
                <line className="grid" x1={M.left} x2={width - M.right} y1={y(t.value)} y2={y(t.value)} />
                <text className="axis" x={M.left - 10} y={y(t.value)} dy="0.32em" textAnchor="end">{t.label}</text>
              </g>
            ))}
            {marks.map(i => (
              <text key={i} className="axis" x={x(i)} y={H - 6} textAnchor={i === n - 1 ? "end" : "middle"}>
                {i === n - 1 ? "now" : `${n - 1 - i} s ago`}
              </text>
            ))}
            {!byProgram && n > 1 && (
              <path className="area" d={`${path(series[0].values)}L${x(n - 1)},${y(0)}L${x(0)},${y(0)}Z`} />
            )}
            {series.map(s => <path key={s.key} className={`line ${s.cls}`} d={path(s.values)} />)}
            {labels.map(l => (
              <text key={l.key} className="end-label" x={x(n - 1) + 10} y={l.y} dy="0.32em">
                {l.label.length > 16 ? `${l.label.slice(0, 15)}…` : l.label}
              </text>
            ))}
            {h != null && (
              <g>
                <line className="crosshair" x1={x(h)} x2={x(h)} y1={M.top} y2={M.top + innerH} />
                {series.map(s => <circle key={s.key} className={`dot ${s.cls}`} cx={x(h)} cy={y(s.values[h])} r="4.5" />)}
              </g>
            )}
          </svg>
        )}
        {width > 0 && peak === 0 && <div className="chart-empty">{empty}</div>}
        {h != null && (
          <div
            className="tooltip"
            style={{ left: Math.min(Math.max(x(h), 110), width - 110), top: 0 }}
          >
            {series.map(s => (
              <span key={s.key} className="tip-row">
                <i className={`key ${s.cls}`} aria-hidden="true" />
                <b>{formatBytes(s.values[h])}/s</b>
                {byProgram && <em>{s.label}</em>}
              </span>
            ))}
            <span>
              {!byProgram && `${totals[h]?.packets.toLocaleString()} packets · `}{formatTime(times[h])}
            </span>
          </div>
        )}
        {/* For screen readers. A table ignores the 1px size, so a div does the hiding. */}
        <div className="sr-only">
          <table>
            <caption>Bytes per second, last minute</caption>
            <thead><tr><th>Time</th>{series.map(s => <th key={s.key}>{s.label}</th>)}</tr></thead>
            <tbody>
              {times.map((t, i) => <tr key={t}><td>{formatTime(t)}</td>{series.map(s => <td key={s.key}>{s.values[i]}</td>)}</tr>)}
            </tbody>
          </table>
        </div>
      </div>
      {byProgram && series.length > 0 && (
        <div className="chart-legend">
          {series.map(s => (
            <span key={s.key}><i className={`key ${s.cls}`} aria-hidden="true" />{s.label}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function FilterBar({ filters, setFilters, error }) {
  const typed = f => ({ host: f.host, port: f.port, q: f.q });
  const [draft, setDraft] = useState(typed(filters));
  // Follow changes made elsewhere, e.g. clicking a host or an alert.
  useEffect(() => setDraft(typed(filters)), [filters.host, filters.port, filters.q]);

  function apply(next = draft) {
    setFilters(f => (f.host === next.host && f.port === next.port && f.q === next.q ? f : { ...f, ...next }));
  }
  // Typed filters apply after a short pause, so each keystroke is not a new query.
  useEffect(() => {
    const timer = setTimeout(() => apply(draft), 400);
    return () => clearTimeout(timer);
  }, [draft]);

  const field = (key, props) => (
    <input
      {...props}
      value={draft[key]}
      onChange={e => setDraft(d => ({ ...d, [key]: e.target.value }))}
      onKeyDown={e => e.key === "Enter" && apply()}
    />
  );
  const active = Object.values(filters).some(v => String(v).trim());

  return (
    <div className="filters">
      <div className="seg" role="group" aria-label="Protocol">
        {["", ...PROTOCOLS].map(p => (
          <button
            key={p || "all"}
            className={filters.proto === p ? "on" : ""}
            aria-pressed={filters.proto === p}
            onClick={() => setFilters(f => ({ ...f, proto: p }))}
          >
            {p || "All"}
          </button>
        ))}
      </div>
      <div className="fields">
        {field("host", { className: "f-host", placeholder: "IP, MAC or subnet", "aria-label": "Host filter" })}
        {field("port", { className: "f-port", placeholder: "Port", inputMode: "numeric", "aria-label": "Port filter" })}
        {field("q", { className: "f-q", placeholder: "Search rows", "aria-label": "Search packets" })}
        {active && <button onClick={() => setFilters(NO_FILTERS)}>Clear</button>}
      </div>
      {error && <div className="filter-error">{error}</div>}
    </div>
  );
}

function PacketTable({ packets, paused, setPaused, selectedId, onSelect, filters, setFilters, filterError, retention, capturing }) {
  const wrap = useRef(null);
  // "newest": newest packet at the top. "oldest": oldest at the top and new
  // packets arrive at the bottom, the way Wireshark lists them.
  const [order, setOrder] = useState("newest");
  // Rows held still while the user has scrolled away from where new packets
  // arrive, so they are not pushed out of view while being read.
  const [held, setHeld] = useState(null);
  const live = packets.slice(0, SHOW_ROWS);
  const newestFirst = held || live;
  const rows = order === "newest" ? newestFirst : [...newestFirst].reverse();
  const newer = held ? packets.filter(p => p.id > (held[0]?.id ?? 0)).length : 0;
  const filtered = Object.values(filters).some(v => String(v).trim());
  const kept = retention ? ` · kept for ${formatRetention(retention)}` : "";

  // Distance from the end of the table where new packets appear.
  function fromLiveEnd(el) {
    return order === "newest" ? el.scrollTop : el.scrollHeight - el.clientHeight - el.scrollTop;
  }
  function jumpToLiveEnd() {
    const el = wrap.current;
    if (el) el.scrollTop = order === "newest" ? 0 : el.scrollHeight;
  }
  function onScroll(e) {
    const away = fromLiveEnd(e.currentTarget) > 8;
    if (away && !held) setHeld(live);
    else if (!away && held) setHeld(null);
  }
  function backToLive() {
    setHeld(null);
    jumpToLiveEnd();
  }
  function toggleOrder() {
    setHeld(null);
    setOrder(o => (o === "newest" ? "oldest" : "newest"));
  }
  // Switching the order starts at the end where new packets arrive.
  useLayoutEffect(jumpToLiveEnd, [order]);
  // Oldest first: follow new packets at the bottom, but only if the user was at
  // the bottom; any distance beyond what the new rows added means they scrolled up.
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
  // A new filter starts again from the newest matching packets.
  useEffect(backToLive, [filterQuery(filters)]);

  const waiting = newer ? ` · ${newer >= KEEP_ROWS ? `${KEEP_ROWS}+` : newer} new packet${newer === 1 ? "" : "s"}` : "";
  return (
    <div className="card" id="packets">
      <div className="card-head">
        <div>
          <div className="label">Live packets</div>
          <div className="muted">
            {filtered ? `${rows.length} matching · ` : ""}{order === "newest" ? "Newest" : "Oldest"} first{kept} &middot; click a row to see its headers
          </div>
        </div>
        <div className="head-buttons">
          <a className="button" href={`/api/export/packets.csv?${filterQuery(filters)}`} download
            title="Download the packets shown (with the current filters) as a spreadsheet">Export CSV</a>
          <a className="button" href={`/api/export/packets.pcap?${filterQuery(filters)}`} download
            title="Download the packets shown as a .pcap file, to open in Wireshark">Export .pcap</a>
          <button className={paused ? "paused" : ""} onClick={() => setPaused(!paused)}>
          {paused ? "Resume" : "Pause"}
          </button>
        </div>
      </div>
      <FilterBar filters={filters} setFilters={setFilters} error={filterError} />
      <div className="table-area">
        {held && (
          <div className={`held ${order === "newest" ? "at-top" : "at-bottom"}`} role="status">
            <span>Held still while you scroll{waiting}</span>
            <button onClick={backToLive}>Back to live</button>
          </div>
        )}
        <div className="table-wrap" ref={wrap} onScroll={onScroll}>
          <table>
            <thead>
              <tr>
                <th aria-sort={order === "newest" ? "descending" : "ascending"}>
                  <button className="sort" onClick={toggleOrder}
                    title={order === "newest" ? "Showing newest first. Click for oldest first." : "Showing oldest first. Click for newest first."}>
                    TIME <span aria-hidden="true">{order === "newest" ? "▼" : "▲"}</span>
                  </button>
                </th>
                <th>APP</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th>
                <th>SERVICE</th><th className="num">BYTES</th><th>INFO</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(p => (
                <tr
                  key={p.id}
                  className={[p.id === selectedId ? "selected" : "", p.tcp_note ? "noted" : ""].join(" ").trim()}
                  onClick={() => onSelect(p)}
                >
                  <td className="time">{formatTime(p.time)}</td>
                  <td className="program" title={p.app || "Program not known (another device, or a replayed file)"}>
                    {p.app || <span className="none">&mdash;</span>}
                  </td>
                  <td>{withPort(p.src, p.sport)}{p.src_name && <span className="hostname">{p.src_name}</span>}</td>
                  <td>{withPort(p.dst, p.dport)}{p.dst_name && <span className="hostname">{p.dst_name}</span>}</td>
                  <td><span className={`badge p-${protoClass(p.proto)}`}>{p.proto}</span></td>
                  <td>{p.service || ""}</td>
                  <td className="num">{p.length}</td>
                  <td className="info">{p.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && (
            <div className="empty">
              {filtered
                ? "No packets match these filters yet."
                : capturing
                  ? <>Waiting for packets&hellip; open a website to generate some traffic.</>
                  : `Capture has stopped, and packets older than ${formatRetention(retention)} have decayed.`}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// POST a JSON action to the sniffer. JSON, so a form on another website cannot do the same.
async function postJSON(url, body = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  if (response.status === 401) window.location.reload();
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok && data.ok !== false, ...data };
}

function AlertCard({ alert, defense, open, onToggle, onFocus, onFix, onUndo, busy }) {
  const fixed = alert.fixed;
  const canFix = defense?.available;
  return (
    <div className={`alert${open ? " open" : ""}`}>
      <div className="alert-head">
        <span className={`sev s-${alert.severity}`}>{SEVERITY_LABEL[alert.severity]}</span>
        <span className="title">{alert.title}</span>
        <span className="when">
          {formatTime(alert.last_seen)}{alert.count > 1 ? ` · ×${alert.count.toLocaleString()}` : ""}
          {fixed && <span className="fixed-tag">FIXED</span>}
        </span>
        <span className="detail">{alert.detail}</span>
      </div>
      <div className="alert-actions">
        <button onClick={() => onFocus(alert.focus)}>Show packets</button>
        {alert.advice && (
          <button className={open ? "on" : ""} aria-expanded={open} onClick={onToggle}>
            {open ? "Hide fix" : "How to fix"}
          </button>
        )}
      </div>
      {open && alert.advice && (
        <div className="fix">
          <p>{alert.advice.meaning}</p>
          <ol>{alert.advice.steps.map(step => <li key={step}>{step}</li>)}</ol>
          {fixed ? (
            <div className="fix-done">
              <span>&#10003; {fixed.label}{fixed.auto ? " (automatically)" : ""}</span>
              <button disabled={busy} onClick={() => onUndo(fixed.id)}>Undo</button>
            </div>
          ) : alert.fix_label ? (
            <div className="fix-do">
              <button className="primary" disabled={!canFix || busy} onClick={() => onFix(alert.id)}>
                {busy ? "Working…" : alert.fix_label}
              </button>
              {!canFix && defense?.reason && <span className="muted">{defense.reason}</span>}
            </div>
          ) : (
            <div className="muted">No one-click fix for this one: follow the steps above.</div>
          )}
        </div>
      )}
    </div>
  );
}

function SecurityPanel({ security, onFocus, refresh }) {
  const [open, setOpen] = useState({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  if (!security) {
    return <div className="card"><div className="card-head"><div className="label">Security</div></div><div className="muted">Loading&hellip;</div></div>;
  }
  if (!security.enabled) {
    return (
      <div className="card">
        <div className="card-head"><div className="label">Security</div></div>
        <div className="muted">Security checks are off. Start without --no-security to turn them on.</div>
      </div>
    );
  }
  const { alerts, rules, checked, defense } = security;
  const applied = defense?.applied || [];

  async function act(url, body) {
    setBusy(true);
    const result = await postJSON(url, body);
    setMessage({ ok: result.ok, text: result.message });
    setBusy(false);
    refresh();
  }

  return (
    <div className="card">
      <div className="card-head">
        <div className="label">Security</div>
        <div className="muted">{checked.toLocaleString()} packets checked</div>
      </div>
      <div className="checks">
        {rules.map(rule => (
          <div className={`check ${rule.alerts ? `hit s-${rule.severity}` : "ok"}`} key={rule.rule}>
            <span className="mark" aria-hidden="true">{rule.alerts ? "!" : "✓"}</span>
            <span className="name">{rule.name}<small>{rule.description}</small></span>
            <span className="state">{rule.alerts ? `${rule.alerts} alert${rule.alerts > 1 ? "s" : ""}` : "OK"}</span>
          </div>
        ))}
      </div>
      {message && (
        <div className={`fix-message ${message.ok ? "good" : "bad"}`} role="status">
          <span>{message.text}</span>
          <button className="link" onClick={() => setMessage(null)}>Dismiss</button>
        </div>
      )}
      {alerts.length === 0 ? (
        <div className="all-clear">No threats detected so far.</div>
      ) : (
        <div className="alerts">
          {alerts.map(a => (
            <AlertCard
              key={a.id}
              alert={a}
              defense={defense}
              open={!!open[a.id]}
              onToggle={() => setOpen(o => ({ ...o, [a.id]: !o[a.id] }))}
              onFocus={onFocus}
              onFix={id => act("/api/defense/apply", { alert_id: id })}
              onUndo={id => act("/api/defense/undo", { fix_id: id })}
              busy={busy}
            />
          ))}
        </div>
      )}
      <div className="protection">
        <div className="protection-head">
          <span className="label">Protection</span>
          <span className="muted">
            {defense?.auto_block ? "Auto-block on" : "Auto-block off"}
            {" · "}
            <a href="/api/export/alerts.csv" download>Export alerts (CSV)</a>
          </span>
        </div>
        {applied.length === 0 ? (
          <div className="muted">
            No fixes applied.{defense && !defense.available && defense.reason ? ` ${defense.reason}` : ""}
          </div>
        ) : (
          applied.map(f => (
            <div className="applied" key={f.id}>
              <span>{f.label}{f.auto ? " (auto)" : ""}<small>{formatTime(f.time)}</small></span>
              <button disabled={busy} onClick={() => act("/api/defense/undo", { fix_id: f.id })}>Undo</button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function CaptureButton({ capture, refresh }) {
  const [busy, setBusy] = useState(false);
  if (!capture) return null;
  const running = capture.running;
  async function toggle() {
    setBusy(true);
    await postJSON(`/api/capture/${running ? "stop" : "start"}`);
    setBusy(false);
    refresh();
  }
  return (
    <button className={`capture-button ${running ? "stop" : "start"}`} disabled={busy} onClick={toggle}>
      {running ? "Stop capture" : "Start capture"}
    </button>
  );
}

function Protocols({ protocols, retention, onPick, picked }) {
  const list = protocols || [];
  return (
    <div className="card">
      <div className="card-head">
        <div className="label">Protocols</div>
        <div className="muted">share of packets{retention ? `, last ${formatRetention(retention)}` : ""}</div>
      </div>
      <div className="stack">
        {list.map(p => <div key={p.name} className={`c-${protoClass(p.name)}`} style={{ width: `${p.percent}%` }} title={`${p.name} ${p.percent}%`} />)}
      </div>
      <div className="legend">
        {list.map(p => (
          <button
            className={`legend-row${picked === p.name ? " on" : ""}`}
            key={p.name}
            onClick={() => onPick(picked === p.name ? "" : p.name)}
            title={picked === p.name ? "Show every protocol" : `Show only ${p.name} packets`}
          >
            <span className={`swatch c-${protoClass(p.name)}`} />
            <span>{p.name}</span>
            <span className="count">{p.packets.toLocaleString()} pkts &middot; {formatBytes(p.bytes)}</span>
            <span className="pct">{p.percent}%</span>
          </button>
        ))}
        {!list.length && <div className="muted">No packets yet.</div>}
      </div>
    </div>
  );
}

function TopApps({ apps, retention, enabled, onPick, picked }) {
  const list = apps || [];
  const max = Math.max(1, ...list.map(a => a.bytes));
  return (
    <div className="card">
      <div className="card-head">
        <div className="label">Top applications</div>
        <div className="muted">programs on this computer{retention ? `, last ${formatRetention(retention)}` : ""}</div>
      </div>
      <div className="hosts">
        {list.map(a => (
          <button
            className={`host app-row${picked === a.app ? " on" : ""}`}
            key={a.app}
            onClick={() => onPick(picked === a.app ? "" : a.app)}
            title={picked === a.app ? "Show every program" : `${a.packets.toLocaleString()} packets. Click to show only ${a.app}.`}
          >
            <span className="name">{a.app}</span>
            <span className="bar"><div style={{ width: `${(100 * a.bytes) / max}%` }} /></span>
            <span className="size">{formatBytes(a.bytes)}</span>
          </button>
        ))}
        {!list.length && (
          <div className="muted">
            {enabled === false
              ? "Shown during live capture. A replayed file does not say which program sent each packet."
              : "No programs named yet."}
          </div>
        )}
      </div>
    </div>
  );
}

function TopHosts({ hosts, retention, onPick }) {
  const list = hosts || [];
  const max = Math.max(1, ...list.map(h => h.bytes));
  return (
    <div className="card">
      <div className="card-head">
        <div className="label">Top hosts</div>
        <div className="muted">bytes sent + received{retention ? `, last ${formatRetention(retention)}` : ""}</div>
      </div>
      <div className="hosts">
        {list.map(h => (
          <button className="host" key={h.host} onClick={() => onPick(h.host)}
            title={`${h.packets.toLocaleString()} packets. Click to show only this host.`}>
            <span className="name">{h.host}{h.name && <small>{h.name}</small>}</span>
            <span className="bar"><div style={{ width: `${(100 * h.bytes) / max}%` }} /></span>
            <span className="size">{formatBytes(h.bytes)}</span>
          </button>
        ))}
        {!list.length && <div className="muted">No hosts yet.</div>}
      </div>
    </div>
  );
}

// ---- small helpers for settings remembered in this browser ----------------------------

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
    try { window.localStorage.setItem(key, JSON.stringify(value)); } catch (err) { /* private window */ }
  }, [key, value]);
  return [value, setValue];
}

// Poll one API address every few seconds while a view is on screen.
function useFetch(url, everyMs) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    let stopped = false;
    async function load() {
      try {
        const body = await getJSON(url);
        if (!stopped) { setData(body); setError(null); }
      } catch (err) {
        if (err.status === 401) window.location.reload();
        else if (!stopped) setError(err.message);
      }
    }
    load();
    const timer = everyMs ? setInterval(load, everyMs) : null;
    return () => { stopped = true; if (timer) clearInterval(timer); };
  }, [url, everyMs]);
  return { data, error };
}

// ---- packet details, with the bytes ----------------------------------------------------

const APP_LAYER = /^(DNS|DHCP|HTTP|TLS)\b/;

function HexView({ packetId }) {
  const { data, error } = useFetch(`/api/packets/${packetId}/bytes`, 0);
  if (error) return <div className="muted">{error}</div>;
  if (!data) return <div className="muted">Loading bytes&hellip;</div>;
  const bytes = data.hex.match(/../g) || [];
  const layerOf = i => data.layers.findIndex(l => i >= l.start && i < l.end);
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 16) rows.push(offset);
  return (
    <div className="hexview">
      <div className="hex-legend">
        {data.layers.map((l, i) => (
          <span key={i} className={`hx l${i % 6}`}>{l.name} <small>{l.end - l.start} B</small></span>
        ))}
      </div>
      <div className="hex-rows" role="table" aria-label="Packet bytes">
        {rows.map(offset => (
          <div className="hex-row" role="row" key={offset}>
            <span className="off">{offset.toString(16).padStart(4, "0")}</span>
            <span className="bytes">
              {bytes.slice(offset, offset + 16).map((b, j) => (
                <span key={j} className={`hx l${layerOf(offset + j) % 6}`}>{b}</span>
              ))}
            </span>
            <span className="ascii">
              {bytes.slice(offset, offset + 16).map((b, j) => {
                const code = parseInt(b, 16);
                return <span key={j} className={`hx l${layerOf(offset + j) % 6}`}>{code > 31 && code < 127 ? String.fromCharCode(code) : "."}</span>;
              })}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function PacketDetails({ packet }) {
  const [showBytes, setShowBytes] = useState(false);
  useEffect(() => setShowBytes(false), [packet?.id]);
  return (
    <div className="card">
      <div className="card-head">
        <div className="label">Packet details</div>
        {packet && (
          <div className="head-buttons">
            <span className="muted">#{packet.id}</span>
            <button onClick={() => setShowBytes(s => !s)} aria-expanded={showBytes}>{showBytes ? "Hide bytes" : "Show bytes"}</button>
          </div>
        )}
      </div>
      {!packet && <div className="muted">Click a packet to see its headers decoded layer by layer.</div>}
      {packet && (
        <div>
          {packet.app && (
            <div className="layer l-app">
              <div className="name">PROGRAM</div>
              <div className="body">{packet.app}<br /><span>sent or received by this program on this computer</span></div>
            </div>
          )}
          {APP_LAYER.test(packet.info) && (
            <div className="layer l-application">
              <div className="name">{packet.info.split(" ")[0]}</div>
              <div className="body">{packet.info.split(" ").slice(1).join(" ")}</div>
            </div>
          )}
          {packet.src_mac && (
            <div className="layer l-link">
              <div className="name">ETHERNET</div>
              <div className="body"><span>src</span> {packet.src_mac}<br /><span>dst</span> {packet.dst_mac}</div>
            </div>
          )}
          {packet.proto === "ARP" ? (
            <div className="layer l-net">
              <div className="name">ARP</div>
              <div className="body">{packet.info}</div>
            </div>
          ) : packet.ip_version && (
            <div className="layer l-net">
              <div className="name">IPv{packet.ip_version}</div>
              <div className="body">
                <span>src</span> {packet.src}{packet.src_name ? ` (${packet.src_name})` : ""}<br />
                <span>dst</span> {packet.dst}{packet.dst_name ? ` (${packet.dst_name})` : ""}<br />
                <span>{packet.ip_version === 6 ? "hop limit" : "ttl"}</span> {packet.ttl}
              </div>
            </div>
          )}
          {["TCP", "UDP", "ICMP"].includes(packet.proto) && (
            <div className="layer l-trans">
              <div className="name">{packet.proto}</div>
              <div className="body">
                {packet.sport != null && <><span>ports</span> {packet.sport} &rarr; {packet.dport}<br /></>}
                {packet.flags.length > 0 && <><span>flags</span> {packet.flags.join(", ")}<br /></>}
                {packet.seq != null && <><span>seq</span> {packet.seq} <span>ack</span> {packet.ack}<br /></>}
                {packet.payload_len > 0 && <><span>data</span> {packet.payload_len} bytes<br /></>}
                {packet.tcp_note && <><span>note</span> <b className="note">{packet.tcp_note}</b><br /></>}
                {packet.service && <><span>service</span> {packet.service}<br /></>}
                {packet.proto === "ICMP" && <><span>type</span> {packet.info}</>}
              </div>
            </div>
          )}
          <div className="layer l-data">
            <div className="name">FRAME</div>
            <div className="body"><span>size</span> {packet.length} bytes<br /><span>time</span> {formatTime(packet.time)}</div>
          </div>
          {showBytes && <HexView packetId={packet.id} />}
        </div>
      )}
    </div>
  );
}

// ---- the other views: connections, devices, history -------------------------------------

function ViewTabs({ view, setView }) {
  const views = [["packets", "Packets"], ["connections", "Connections"], ["devices", "Devices"], ["history", "History"]];
  return (
    <div className="view-tabs" role="tablist" aria-label="Views">
      {views.map(([key, text]) => (
        <button key={key} role="tab" aria-selected={view === key} className={view === key ? "on" : ""}
          onClick={() => setView(key)}>{text}</button>
      ))}
    </div>
  );
}

function Tiles({ items }) {
  return (
    <div className="summary">
      {items.map(item => (
        <div className="metric" key={item.label}>
          <div className="label">{item.label}</div>
          <div className="value">{item.value}</div>
          <div className="sub">{item.sub}</div>
        </div>
      ))}
    </div>
  );
}

const STATE_CLASS = { established: "good", "SYN sent": "wait", "SYN received": "wait", closing: "wait",
                      closed: "done", reset: "bad", active: "good", "joined late": "done" };

function ConnectionsView({ onFocus }) {
  const { data } = useFetch("/api/connections?limit=500", 2000);
  const [query, setQuery] = useState("");
  const all = data?.connections || [];
  const q = query.trim().toLowerCase();
  const rows = q ? all.filter(c => [c.client, c.server, c.server_name, c.app, c.state, c.proto, c.service]
    .some(v => v && String(v).toLowerCase().includes(q))) : all;
  const s = data?.summary || {};
  return (
    <>
      <Tiles items={[
        { label: "Connections", value: (s.connections ?? 0).toLocaleString(), sub: `${s.tcp ?? 0} TCP · ${s.udp ?? 0} UDP` },
        { label: "Average round trip", value: s.avg_rtt_ms != null ? `${s.avg_rtt_ms} ms` : "-", sub: "SYN to SYN-ACK" },
        { label: "Retransmissions", value: `${s.retransmission_percent ?? 0}%`, sub: "of TCP packets sent again" },
        { label: "Duplicate ACKs", value: (s.dup_acks ?? 0).toLocaleString(), sub: "receivers asking for lost data" },
      ]} />
      <div className="card">
        <div className="card-head">
          <div>
            <div className="label">Connections</div>
            <div className="muted">Newest activity first &middot; click one to see its packets</div>
          </div>
          <input className="search" placeholder="Search connections" value={query} onChange={e => setQuery(e.target.value)}
            aria-label="Search connections" />
        </div>
        <div className="table-wrap tall">
          <table>
            <thead>
              <tr>
                <th>LAST SEEN</th><th>APP</th><th>CLIENT</th><th>SERVER</th><th>PROTO</th><th>STATE</th>
                <th className="num">ROUND TRIP</th><th className="num">SENT</th><th className="num">RECEIVED</th>
                <th className="num">RETRANS.</th><th className="num">DURATION</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(c => (
                <tr key={c.id} onClick={() => onFocus(c.server)} title="Show this connection's packets">
                  <td className="time">{formatTime(c.last_seen)}</td>
                  <td className="program">{c.app || <span className="none">&mdash;</span>}</td>
                  <td>{withPort(c.client, c.client_port)}</td>
                  <td>{withPort(c.server, c.server_port)}{c.server_name && <span className="hostname">{c.server_name}</span>}</td>
                  <td><span className={`badge p-${protoClass(c.proto)}`}>{c.proto}</span></td>
                  <td><span className={`state ${STATE_CLASS[c.state] || ""}`}>{c.state}</span></td>
                  <td className="num">{c.rtt_ms != null ? `${c.rtt_ms} ms` : "-"}</td>
                  <td className="num">{formatBytes(c.bytes_out)}</td>
                  <td className="num">{formatBytes(c.bytes_in)}</td>
                  <td className="num">{c.retransmissions || ""}</td>
                  <td className="num">{formatDuration(c.duration)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <div className="empty">{q ? "No connections match." : "No connections yet."}</div>}
        </div>
      </div>
    </>
  );
}

function DevicesView({ onFocus }) {
  const { data } = useFetch("/api/devices", 3000);
  const devices = data?.devices || [];
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <div className="label">Devices on this network</div>
          <div className="muted">Seen in their own traffic &middot; maker from the MAC address &middot; name from DHCP</div>
        </div>
        <span className="muted">{devices.length} found</span>
      </div>
      <div className="devices">
        {devices.map(d => (
          <button className="device" key={d.mac} onClick={() => onFocus(d.mac)} title="Show this device's packets">
            <span className="device-name">
              {d.name || d.maker || "Unknown device"}
              {d.is_this_computer && <span className="tag">THIS COMPUTER</span>}
              {d.is_router && <span className="tag">ROUTER</span>}
            </span>
            <span className="muted">{d.name ? d.maker || "unknown maker" : ""}</span>
            <span className="mono">{d.addresses.join(", ") || "no address seen"}</span>
            <span className="mono muted">{d.mac}</span>
            <span className="muted">{d.packets.toLocaleString()} packets &middot; {formatBytes(d.bytes)} &middot; last {formatTime(d.last_seen)}</span>
          </button>
        ))}
        {!devices.length && <div className="muted">No devices seen yet.</div>}
      </div>
    </div>
  );
}

function HistoryView() {
  const [hours, setHours] = useState(24);
  const { data, error } = useFetch(`/api/history?hours=${hours}`, 10000);
  if (data && !data.enabled) {
    return <div className="card"><div className="muted">History is off. Start without --no-history to keep it.</div></div>;
  }
  const maxServer = Math.max(1, ...(data?.top_servers || []).map(s => s.bytes_in + s.bytes_out));
  return (
    <>
      <div className="card">
        <div className="card-head">
          <div>
            <div className="label">History</div>
            <div className="muted">
              Kept between runs for {data?.keep_days ?? 7} days{data?.path ? ` in ${data.path}` : ""}
              {error ? ` · ${error}` : ""}{data?.error ? ` · ${data.error}` : ""}
            </div>
          </div>
          <div className="seg small" role="group" aria-label="Time range">
            {[[1, "1 hour"], [6, "6 hours"], [24, "24 hours"], [168, "7 days"]].map(([h, text]) => (
              <button key={h} className={hours === h ? "on" : ""} aria-pressed={hours === h} onClick={() => setHours(h)}>{text}</button>
            ))}
          </div>
        </div>
        <div className="history-grid">
          <div>
            <div className="label sub-label">Sessions</div>
            {(data?.sessions || []).map(s => (
              <div className="history-row" key={s.id}>
                <span>{s.mode === "replay" ? "Replay" : "Live"} &middot; {String(s.source).split(/[\\/]/).pop()}</span>
                <span className="muted">{formatTime(s.started)} &ndash; {formatTime(s.ended)} &middot; {(s.packets || 0).toLocaleString()} packets &middot; {formatBytes(s.bytes)}</span>
              </div>
            ))}
            {!data?.sessions?.length && <div className="muted">No sessions in this time.</div>}
          </div>
          <div>
            <div className="label sub-label">Busiest servers</div>
            {(data?.top_servers || []).map(s => (
              <div className="host" key={s.server}>
                <span className="name">{s.server}{s.name && <small>{s.name}</small>}</span>
                <span className="bar"><div style={{ width: `${(100 * (s.bytes_in + s.bytes_out)) / maxServer}%` }} /></span>
                <span className="size">{formatBytes(s.bytes_in + s.bytes_out)}</span>
              </div>
            ))}
            {!data?.top_servers?.length && <div className="muted">No connections in this time.</div>}
          </div>
        </div>
      </div>
      <div className="card">
        <div className="card-head"><div className="label">Alerts in this time</div></div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>LAST SEEN</th><th>SEVERITY</th><th>ALERT</th><th className="num">TIMES</th></tr></thead>
            <tbody>
              {(data?.alerts || []).map((a, i) => (
                <tr key={`${a.session}-${i}`}>
                  <td className="time">{formatTime(a.last_seen)}</td>
                  <td><span className={`sev s-${a.severity}`}>{SEVERITY_LABEL[a.severity]}</span></td>
                  <td className="wrap"><b>{a.title}</b><span className="hostname">{a.detail}</span></td>
                  <td className="num">{a.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!data?.alerts?.length && <div className="empty">No alerts in this time.</div>}
        </div>
      </div>
    </>
  );
}

// ---- top bar: settings, theme, text size, alerts, report ---------------------------------

function SettingsPanel({ onClose, refresh }) {
  const { data } = useFetch("/api/interfaces", 0);
  const [iface, setIface] = useState(null);
  const [filter, setFilter] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const chosen = iface ?? data?.current ?? "";
  const bpf = filter ?? data?.filter ?? "";
  const live = data?.mode === "live";

  async function apply() {
    setBusy(true);
    const result = await postJSON("/api/capture/start", { iface: chosen, filter: bpf });
    setBusy(false);
    setMessage({ ok: result.ok, text: result.ok ? "Capture restarted with these settings." : result.message });
    if (result.ok) refresh();
  }

  return (
    <div className="popover" role="dialog" aria-label="Capture settings">
      <div className="card-head">
        <div className="label">Capture settings</div>
        <button className="link" onClick={onClose}>Close</button>
      </div>
      {!live && data && <p className="muted">Replaying a file: interface and filter apply to live capture only.</p>}
      <label className="field-label" htmlFor="iface">Interface</label>
      <select id="iface" value={chosen} disabled={!live} onChange={e => setIface(e.target.value)}>
        {(data?.interfaces || []).map(i => (
          <option key={i.name} value={i.name}>{i.name}{i.ips.length ? ` (${i.ips[0]})` : ""}{i.default ? " · default" : ""}</option>
        ))}
      </select>
      <label className="field-label" htmlFor="bpf">Capture filter (BPF)</label>
      <input id="bpf" className="mono-input" value={bpf} disabled={!live} placeholder="e.g. tcp port 443, or host 192.168.1.5"
        onChange={e => setFilter(e.target.value)} />
      <p className="muted">Only matching packets are captured at all. Leave empty to capture everything.</p>
      {message && <div className={`fix-message ${message.ok ? "good" : "bad"}`}>{message.text}</div>}
      <button className="primary" disabled={!live || busy} onClick={apply}>{busy ? "Restarting…" : "Apply and restart capture"}</button>
    </div>
  );
}

const THEMES = ["auto", "light", "dark"];

function useAppearance() {
  const [theme, setTheme] = useSetting("sniffer.theme", "auto");
  const [large, setLarge] = useSetting("sniffer.large", false);
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "auto") delete root.dataset.theme; else root.dataset.theme = theme;
    if (large) root.dataset.size = "large"; else delete root.dataset.size;
  }, [theme, large]);
  return { theme, cycleTheme: () => setTheme(t => THEMES[(THEMES.indexOf(t) + 1) % THEMES.length]), large, setLarge };
}

// A desktop pop-up and a short sound for every new high-severity alert, if turned on.
function useAlertNotifications(security, enabled) {
  const seen = useRef(null);
  useEffect(() => {
    const high = (security?.alerts || []).filter(a => a.severity === "high");
    if (seen.current === null) {           // first load: only alerts after this count
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
    } catch (err) { /* no sound available */ }
    if ("Notification" in window && Notification.permission === "granted") {
      fresh.forEach(a => new Notification(`Security alert: ${a.title}`, { body: a.detail, tag: `alert-${a.id}` }));
    }
  }, [security, enabled]);
}

function TopbarTools({ capture, refresh, notify, setNotify }) {
  const { theme, cycleTheme, large, setLarge } = useAppearance();
  const [settings, setSettings] = useState(false);

  async function toggleNotify() {
    if (!notify && "Notification" in window && Notification.permission === "default") {
      try { await Notification.requestPermission(); } catch (err) { /* older browsers */ }
    }
    setNotify(!notify);
  }

  return (
    <div className="tools">
      <button className="tool" onClick={() => setSettings(s => !s)} aria-expanded={settings} title="Interface and capture filter">
        Settings
      </button>
      <button className="tool" onClick={toggleNotify} aria-pressed={notify}
        title={notify ? "Pop-up and sound for high-severity alerts: on" : "Pop-up and sound for high-severity alerts: off"}>
        Alerts: {notify ? "on" : "off"}
      </button>
      <button className="tool" onClick={cycleTheme} title="Light, dark, or follow the computer">
        Theme: {theme}
      </button>
      <button className="tool" onClick={() => setLarge(!large)} aria-pressed={large} title="Larger text, for projectors">
        {large ? "Normal text" : "Large text"}
      </button>
      <a className="tool" href="/report" target="_blank" rel="noopener">Report</a>
      {settings && <SettingsPanel onClose={() => setSettings(false)} refresh={refresh} capture={capture} />}
    </div>
  );
}

function App() {
  const [filters, setFilters] = useState(NO_FILTERS);
  const { packets, stats, security, offline, paused, setPaused, filterError, refresh } = usePolling(filters);
  const [selected, setSelected] = useState(null);
  const [view, setView] = useSetting("sniffer.view", "packets");
  const [notify, setNotify] = useSetting("sniffer.notify", false);
  useAlertNotifications(security, notify);

  const capture = stats?.capture;
  const retention = stats?.retention;

  // Show only one host's packets, e.g. the source of an alert, and bring the table into view.
  function focusHost(host) {
    if (!host) return;
    setFilters({ ...NO_FILTERS, host });
    setView("packets");
    setTimeout(() => {
      const table = document.getElementById("packets");
      if (table && table.getBoundingClientRect().top < 0) table.scrollIntoView({ behavior: "smooth" });
    }, 0);
  }

  return (
    <>
    <header className="topbar">
      <div className="topbar-inner">
        <div className="brand">
          <div className="layers"><span>ETH</span><span>IP</span><span>TCP/UDP</span></div>
          <h1>Packet Sniffer Dashboard</h1>
        </div>
        <div className="topbar-right">
          <StatusPill capture={capture} offline={offline} />
          {!offline && <CaptureButton capture={capture} refresh={refresh} />}
        </div>
      </div>
      <div className="topbar-inner tools-row">
        <ViewTabs view={view} setView={setView} />
        <TopbarTools capture={capture} refresh={refresh} notify={notify} setNotify={setNotify} />
      </div>
    </header>
    <div className="app">
      <Banners capture={capture} security={security} onFocus={focusHost} />

      {view === "packets" && (
        <>
          <Summary stats={stats} />
          <BandwidthChart points={stats?.bandwidth} apps={stats?.app_bandwidth} appsEnabled={capture?.apps} />
          <div className="grid">
            <PacketTable
              packets={packets}
              paused={paused}
              setPaused={setPaused}
              selectedId={selected?.id}
              onSelect={setSelected}
              filters={filters}
              setFilters={setFilters}
              filterError={filterError}
              retention={retention}
              capturing={capture?.running ?? true}
            />
            <div className="side">
              {/* First, so a clicked packet's headers are always on screen */}
              <PacketDetails packet={selected} />
              <SecurityPanel security={security} onFocus={focusHost} refresh={refresh} />
              <Protocols
                protocols={stats?.protocols}
                retention={retention}
                picked={filters.proto}
                onPick={proto => setFilters(f => ({ ...f, proto }))}
              />
              <TopApps
                apps={stats?.top_apps}
                retention={retention}
                enabled={capture?.apps}
                picked={filters.q}
                onPick={app => setFilters({ ...NO_FILTERS, q: app })}
              />
              <TopHosts hosts={stats?.top_hosts} retention={retention} onPick={focusHost} />
            </div>
          </div>
        </>
      )}
      {view === "connections" && <ConnectionsView onFocus={focusHost} />}
      {view === "devices" && <DevicesView onFocus={focusHost} />}
      {view === "history" && <HistoryView />}
      <footer className="footer">
        Packet Sniffer {stats?.version || ""} &middot; team Big Packet &middot; capture only on your own device and network
      </footer>
    </div>
    </>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
