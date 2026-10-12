// Packet Sniffer Dashboard: polls the Flask API once a second and redraws.
const { useEffect, useRef, useState } = React;

const POLL_MS = 1000;
const KEEP_ROWS = 300;   // packets kept in the browser
const SHOW_ROWS = 150;   // packets drawn in the table

function formatBytes(n) {
  if (n == null) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function formatTime(epochSeconds) {
  return new Date(epochSeconds * 1000).toLocaleTimeString("en-GB", { hour12: false });
}

function formatDuration(seconds) {
  const s = Math.floor(seconds || 0);
  const m = Math.floor(s / 60);
  return m ? `${m}m ${s % 60}s` : `${s}s`;
}

function protoClass(proto) {
  return ["TCP", "UDP", "ICMP", "ARP"].includes(proto) ? proto : "Other";
}

function withPort(host, port) {
  return port == null ? host || "-" : `${host}:${port}`;
}

async function getJSON(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  return response.json();
}

function usePolling() {
  const [packets, setPackets] = useState([]);
  const [stats, setStats] = useState(null);
  const [offline, setOffline] = useState(false);
  const [paused, setPaused] = useState(false);
  const lastId = useRef(0);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    let stopped = false;

    async function tick() {
      try {
        const s = await getJSON("/api/stats");
        // The server restarted and its packet ids began again from 1.
        if (s.last_id < lastId.current) {
          lastId.current = 0;
          setPackets([]);
        }
        if (!pausedRef.current) {
          const p = await getJSON(`/api/packets?after=${lastId.current}&limit=${SHOW_ROWS}`);
          if (p.packets.length) {
            lastId.current = p.packets[p.packets.length - 1].id;
            setPackets(prev => [...p.packets.reverse(), ...prev].slice(0, KEEP_ROWS));
          }
        }
        if (!stopped) { setStats(s); setOffline(false); }
      } catch (err) {
        if (!stopped) setOffline(true);
      }
    }

    tick();
    const timer = setInterval(tick, POLL_MS);
    return () => { stopped = true; clearInterval(timer); };
  }, []);

  return { packets, stats, offline, paused, setPaused };
}

function StatusPill({ capture, offline }) {
  if (offline) {
    return <div className="status error"><span className="dot" /><b>OFFLINE</b> sniffer.py is not running</div>;
  }
  if (!capture) return <div className="status"><span className="dot" />Connecting&hellip;</div>;
  if (capture.error) {
    return <div className="status error"><span className="dot" /><b>STOPPED</b> {capture.source}</div>;
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

function PacketTable({ packets, paused, setPaused, selectedId, onSelect }) {
  const rows = packets.slice(0, SHOW_ROWS);
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <div className="label">Live packets</div>
          <div className="muted">Newest first &middot; click a row to see its headers</div>
        </div>
        <button className={paused ? "paused" : ""} onClick={() => setPaused(!paused)}>
          {paused ? "Resume" : "Pause"}
        </button>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th>
              <th>SERVICE</th><th className="num">BYTES</th><th>INFO</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(p => (
              <tr
                key={p.id}
                className={p.id === selectedId ? "selected" : ""}
                onClick={() => onSelect(p)}
              >
                <td className="time">{formatTime(p.time)}</td>
                <td>{withPort(p.src, p.sport)}</td>
                <td>{withPort(p.dst, p.dport)}</td>
                <td><span className={`badge p-${protoClass(p.proto)}`}>{p.proto}</span></td>
                <td>{p.service || ""}</td>
                <td className="num">{p.length}</td>
                <td className="info">{p.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <div className="empty">Waiting for packets&hellip; open a website to generate some traffic.</div>}
      </div>
    </div>
  );
}

function Protocols({ protocols }) {
  const list = protocols || [];
  return (
    <div className="card">
      <div className="card-head"><div className="label">Protocols</div><div className="muted">share of packets</div></div>
      <div className="stack">
        {list.map(p => <div key={p.name} className={`c-${protoClass(p.name)}`} style={{ width: `${p.percent}%` }} title={`${p.name} ${p.percent}%`} />)}
      </div>
      <div className="legend">
        {list.map(p => (
          <div className="legend-row" key={p.name}>
            <span className={`swatch c-${protoClass(p.name)}`} />
            <span>{p.name}</span>
            <span className="count">{p.packets.toLocaleString()} pkts &middot; {formatBytes(p.bytes)}</span>
            <span className="pct">{p.percent}%</span>
          </div>
        ))}
        {!list.length && <div className="muted">No packets yet.</div>}
      </div>
    </div>
  );
}

function TopHosts({ hosts }) {
  const list = hosts || [];
  const max = Math.max(1, ...list.map(h => h.bytes));
  return (
    <div className="card">
      <div className="card-head"><div className="label">Top hosts</div><div className="muted">bytes sent + received</div></div>
      <div className="hosts">
        {list.map(h => (
          <div className="host" key={h.host} title={`${h.packets.toLocaleString()} packets`}>
            <span className="name">{h.host}</span>
            <span className="bar"><div style={{ width: `${(100 * h.bytes) / max}%` }} /></span>
            <span className="size">{formatBytes(h.bytes)}</span>
          </div>
        ))}
        {!list.length && <div className="muted">No hosts yet.</div>}
      </div>
    </div>
  );
}

function PacketDetails({ packet }) {
  return (
    <div className="card">
      <div className="card-head"><div className="label">Packet details</div>{packet && <div className="muted">#{packet.id}</div>}</div>
      {!packet && <div className="muted">Click a packet to see its headers decoded layer by layer.</div>}
      {packet && (
        <div>
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
                <span>src</span> {packet.src}<br /><span>dst</span> {packet.dst}<br />
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
                {packet.service && <><span>service</span> {packet.service}<br /></>}
                {packet.proto === "ICMP" && <><span>type</span> {packet.info}</>}
              </div>
            </div>
          )}
          <div className="layer l-data">
            <div className="name">FRAME</div>
            <div className="body"><span>size</span> {packet.length} bytes<br /><span>time</span> {formatTime(packet.time)}</div>
          </div>
        </div>
      )}
    </div>
  );
}

function App() {
  const { packets, stats, offline, paused, setPaused } = usePolling();
  const [selected, setSelected] = useState(null);

  const capture = stats?.capture;

  return (
    <>
    <header className="topbar">
      <div className="topbar-inner">
        <div className="brand">
          <div className="layers"><span>ETH</span><span>IP</span><span>TCP/UDP</span></div>
          <h1>Packet Sniffer Dashboard</h1>
        </div>
        <StatusPill capture={capture} offline={offline} />
      </div>
    </header>
    <div className="app">

      {capture?.error && (
        <div className="banner error"><span className="tag">CAPTURE</span><span>{capture.error}</span></div>
      )}
      {capture?.mode === "replay" && !capture.error && (
        <div className="banner info">
          <span className="tag">REPLAY</span>
          <span>Showing packets from a saved capture file, not live traffic. Run without --pcap to capture live.</span>
        </div>
      )}

      <Summary stats={stats} />

      <div className="grid">
        <PacketTable
          packets={packets}
          paused={paused}
          setPaused={setPaused}
          selectedId={selected?.id}
          onSelect={setSelected}
        />
        <div className="side">
          {/* First, so a clicked packet's headers are always on screen */}
          <PacketDetails packet={selected} />
          <Protocols protocols={stats?.protocols} />
          <TopHosts hosts={stats?.top_hosts} />
        </div>
      </div>
    </div>
    </>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
