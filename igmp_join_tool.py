#!/usr/bin/env python3
"""IGMP Test Tool — cross-platform multicast subscription GUI.

Runs a local web GUI (stdlib only, no dependencies) that lets you join
multicast groups (ASM or SSM) on a selected network interface and shows
live receive statistics.

Usage:
    python3 igmp_join_tool.py            # opens browser automatically
    python3 igmp_join_tool.py --port 9000 --no-browser
"""

import argparse
import ipaddress
import json
import platform
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SYSTEM = platform.system()

# ip_mreq_source option constants differ per OS; Python's socket module
# doesn't define them everywhere.
if SYSTEM == "Linux":
    IP_ADD_SOURCE_MEMBERSHIP = getattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 39)
    IP_DROP_SOURCE_MEMBERSHIP = getattr(socket, "IP_DROP_SOURCE_MEMBERSHIP", 40)
elif SYSTEM == "Windows":
    IP_ADD_SOURCE_MEMBERSHIP = getattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 15)
    IP_DROP_SOURCE_MEMBERSHIP = getattr(socket, "IP_DROP_SOURCE_MEMBERSHIP", 16)
else:  # Darwin / BSD
    IP_ADD_SOURCE_MEMBERSHIP = getattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 70)
    IP_DROP_SOURCE_MEMBERSHIP = getattr(socket, "IP_DROP_SOURCE_MEMBERSHIP", 71)


def pack_mreq(group, iface):
    """struct ip_mreq: same layout everywhere."""
    return socket.inet_aton(group) + socket.inet_aton(iface)


def pack_mreq_source(group, source, iface):
    """struct ip_mreq_source: field order differs between Linux and Windows/BSD."""
    g, s, i = (socket.inet_aton(x) for x in (group, source, iface))
    if SYSTEM == "Linux":
        return g + i + s  # imr_multiaddr, imr_interface, imr_sourceaddr
    return g + s + i      # imr_multiaddr, imr_sourceaddr, imr_interface


def list_interfaces():
    """Return [{'name': ..., 'ip': ...}] of IPv4-capable interfaces."""
    ifaces = []
    try:
        if SYSTEM == "Darwin":
            out = subprocess.check_output(["ifconfig", "-a"], text=True, errors="replace")
            cur = None
            for line in out.splitlines():
                m = re.match(r"^([A-Za-z0-9\.\-]+):", line)
                if m:
                    cur = m.group(1)
                    continue
                m = re.match(r"^\s+inet (\d+\.\d+\.\d+\.\d+)", line)
                if m and cur:
                    ifaces.append({"name": cur, "ip": m.group(1)})
        elif SYSTEM == "Windows":
            ps = ("Get-NetIPAddress -AddressFamily IPv4 | "
                  "Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress")
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps],
                text=True, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for e in data:
                ifaces.append({"name": e["InterfaceAlias"], "ip": e["IPAddress"]})
        else:  # Linux
            out = subprocess.check_output(["ip", "-j", "-4", "addr", "show"], text=True)
            for e in json.loads(out):
                for a in e.get("addr_info", []):
                    if a.get("family") == "inet":
                        ifaces.append({"name": e["ifname"], "ip": a["local"]})
    except Exception as exc:  # noqa: BLE001
        print(f"interface enumeration failed: {exc}", file=sys.stderr)
    # loopback last, everything else in system order
    ifaces.sort(key=lambda i: i["ip"].startswith("127."))
    return ifaces


class Join:
    _next_id = 1
    _id_lock = threading.Lock()

    def __init__(self, group, source, iface_ip, iface_name, port):
        with Join._id_lock:
            self.id = Join._next_id
            Join._next_id += 1
        self.group = group
        self.source = source or None
        self.iface_ip = iface_ip
        self.iface_name = iface_name
        self.port = port or None
        self.started = time.time()
        self.packets = 0
        self.bytes = 0
        self.rx_error = False
        self._stop = threading.Event()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass

        bind_port = self.port or 0
        if SYSTEM == "Windows":
            self.sock.bind(("", bind_port))
        else:
            # binding to the group filters out unrelated traffic on the port
            try:
                self.sock.bind((group, bind_port))
            except OSError:
                self.sock.bind(("", bind_port))

        try:
            if self.source:
                self.sock.setsockopt(socket.IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
                                     pack_mreq_source(group, self.source, iface_ip))
            else:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                     pack_mreq(group, iface_ip))
        except OSError:
            self.sock.close()
            raise

        if self.port:
            self.sock.settimeout(0.5)
            t = threading.Thread(target=self._recv_loop, daemon=True)
            t.start()

    def _recv_loop(self):
        # Survives the interface going down (Windows raises on recv then):
        # mark the join as broken, keep the thread alive, and try to re-add
        # the membership until the interface is back.
        while not self._stop.is_set():
            try:
                data = self.sock.recv(65536)
                self.packets += 1
                self.bytes += len(data)
                self.rx_error = False
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                self.rx_error = True
                self._stop.wait(1.0)
                self._try_rejoin()
            except Exception:  # noqa: BLE001
                if self._stop.is_set():
                    break
                self.rx_error = True
                self._stop.wait(1.0)

    def _try_rejoin(self):
        try:
            if self.source:
                mreq = pack_mreq_source(self.group, self.source, self.iface_ip)
                try:
                    self.sock.setsockopt(socket.IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, mreq)
                except OSError:
                    pass
                self.sock.setsockopt(socket.IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, mreq)
            else:
                mreq = pack_mreq(self.group, self.iface_ip)
                try:
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                except OSError:
                    pass
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.rx_error = False
        except OSError:
            pass  # interface still down — retry on next loop iteration

    def leave(self):
        self._stop.set()
        try:
            if self.source:
                self.sock.setsockopt(socket.IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP,
                                     pack_mreq_source(self.group, self.source, self.iface_ip))
            else:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                     pack_mreq(self.group, self.iface_ip))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def to_dict(self):
        return {
            "id": self.id,
            "group": self.group,
            "source": self.source,
            "iface_ip": self.iface_ip,
            "iface_name": self.iface_name,
            "port": self.port,
            "uptime": int(time.time() - self.started),
            "packets": self.packets,
            "bytes": self.bytes,
            "error": self.rx_error,
        }


JOINS = {}
JOINS_LOCK = threading.Lock()


def api_join(body):
    group = (body.get("group") or "").strip()
    source = (body.get("source") or "").strip()
    iface_ip = (body.get("iface_ip") or "").strip()
    iface_name = (body.get("iface_name") or "").strip()
    port_raw = body.get("port")

    try:
        if not ipaddress.ip_address(group).is_multicast:
            return {"error": f"{group} ist keine Multicast-Adresse (224.0.0.0/4)"}
    except ValueError:
        return {"error": f"Ungültige Multicast-Adresse: {group!r}"}
    if source:
        try:
            src = ipaddress.ip_address(source)
            if src.is_multicast:
                return {"error": "SSM-Source muss eine Unicast-Adresse sein"}
        except ValueError:
            return {"error": f"Ungültige Source-Adresse: {source!r}"}
    try:
        ipaddress.ip_address(iface_ip)
    except ValueError:
        return {"error": "Bitte ein Interface auswählen"}
    port = None
    if port_raw not in (None, ""):
        try:
            port = int(port_raw)
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return {"error": f"Ungültiger Port: {port_raw!r}"}

    with JOINS_LOCK:
        for j in JOINS.values():
            if (j.group, j.source or "", j.iface_ip) == (group, source, iface_ip):
                return {"error": "Dieser Join ist bereits aktiv"}
        try:
            j = Join(group, source, iface_ip, iface_name, port)
        except OSError as exc:
            return {"error": f"Join fehlgeschlagen: {exc}"}
        JOINS[j.id] = j
    return {"ok": True, "join": j.to_dict()}


def api_leave(body):
    jid = body.get("id")
    with JOINS_LOCK:
        j = JOINS.pop(jid, None)
    if j:
        j.leave()
        return {"ok": True}
    return {"error": "Join nicht gefunden"}


def api_leave_all():
    with JOINS_LOCK:
        joins = list(JOINS.values())
        JOINS.clear()
    for j in joins:
        j.leave()
    return {"ok": True, "left": len(joins)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence request logging
        pass

    def _send_json(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            data = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/api/interfaces":
            self._send_json({"interfaces": list_interfaces(), "system": SYSTEM})
        elif self.path == "/api/joins":
            with JOINS_LOCK:
                self._send_json({"joins": [j.to_dict() for j in JOINS.values()],
                                 "now": time.time()})
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send_json({"error": "bad json"}, 400)
            return
        if self.path == "/api/join":
            self._send_json(api_join(body))
        elif self.path == "/api/leave":
            self._send_json(api_leave(body))
        elif self.path == "/api/leave_all":
            self._send_json(api_leave_all())
        else:
            self.send_error(404)


INDEX_HTML = r"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IGMP Test Tool</title>
<style>
  :root {
    --bg: #0e1116; --panel: #161b22; --panel2: #1c2330;
    --border: #2b3442; --text: #e6edf3; --muted: #8b98a9;
    --accent: #3fb68b; --accent2: #2f9d77; --danger: #e5534b;
    --mono: "SF Mono", ui-monospace, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif;
  }
  header {
    display: flex; align-items: baseline; gap: 12px;
    padding: 20px 28px 0;
  }
  header h1 { font-size: 20px; margin: 0; letter-spacing: .3px; }
  header .sys { color: var(--muted); font-size: 13px; }
  main { max-width: 980px; margin: 0 auto; padding: 18px 24px 48px; }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px; margin-top: 18px;
  }
  .grid {
    display: grid; gap: 14px;
    grid-template-columns: 1.4fr 1.2fr 1.2fr .7fr auto;
    align-items: end;
  }
  @media (max-width: 820px) { .grid { grid-template-columns: 1fr 1fr; } }
  label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 5px; }
  label b { color: var(--text); font-weight: 600; }
  input, select {
    width: 100%; padding: 9px 11px; border-radius: 8px;
    border: 1px solid var(--border); background: var(--panel2);
    color: var(--text); font-family: var(--mono); font-size: 14px;
  }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  button {
    padding: 10px 18px; border-radius: 8px; border: none; cursor: pointer;
    background: var(--accent); color: #06130d; font-weight: 700; font-size: 14px;
  }
  button:hover { background: var(--accent2); }
  button.ghost {
    background: transparent; color: var(--muted);
    border: 1px solid var(--border); font-weight: 500;
  }
  button.ghost:hover { color: var(--text); border-color: var(--muted); }
  button.leave {
    background: transparent; color: var(--danger);
    border: 1px solid var(--danger); padding: 6px 14px; font-weight: 600;
  }
  button.leave:hover { background: var(--danger); color: #fff; }
  .toolbar { display: flex; justify-content: space-between; align-items: center; margin-top: 26px; }
  .toolbar h2 { font-size: 15px; margin: 0; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th {
    text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
    color: var(--muted); padding: 10px 12px; border-bottom: 1px solid var(--border);
  }
  td { padding: 11px 12px; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 13.5px; }
  tr:last-child td { border-bottom: none; }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 8px; background: #55606e; }
  .dot.rx { background: var(--accent); box-shadow: 0 0 8px var(--accent); animation: pulse 1.2s infinite; }
  .dot.err { background: var(--danger); box-shadow: 0 0 8px var(--danger); }
  .errtext { color: var(--danger); }
  @keyframes pulse { 50% { opacity: .45; } }
  .muted { color: var(--muted); }
  .rate { color: var(--accent); font-weight: 600; }
  #msg {
    margin-top: 12px; padding: 10px 14px; border-radius: 8px; font-size: 14px;
    display: none; border: 1px solid var(--danger); color: var(--danger);
    background: rgba(229, 83, 75, .08);
  }
  .empty { color: var(--muted); text-align: center; padding: 28px 0; font-size: 14px; }
  .hint { color: var(--muted); font-size: 12.5px; margin: 14px 2px 0; }
</style>
</head>
<body>
<header>
  <h1>IGMP Test Tool</h1>
  <span class="sys" id="sys"></span>
</header>
<main>
  <div class="card">
    <div class="grid">
      <div>
        <label><b>Multicast-Gruppe</b> *</label>
        <input id="group" placeholder="239.1.1.1" spellcheck="false">
      </div>
      <div>
        <label><b>Source</b> (optional, SSM)</label>
        <input id="source" placeholder="z.B. 192.168.10.5" spellcheck="false">
      </div>
      <div>
        <label><b>Interface</b> *</label>
        <select id="iface"></select>
      </div>
      <div>
        <label><b>UDP-Port</b> (optional)</label>
        <input id="port" placeholder="5004" inputmode="numeric" spellcheck="false">
      </div>
      <div>
        <button id="joinBtn">Join</button>
      </div>
    </div>
    <div id="msg"></div>
    <p class="hint">Ohne Source wird ein ASM-Join (IGMPv2/v3) gesendet, mit Source ein SSM-Join (IGMPv3, INCLUDE).
    Mit Port zählt das Tool empfangene Pakete und zeigt die Bitrate an — ohne Port wird nur der Join gehalten.</p>
  </div>

  <div class="toolbar">
    <h2>Aktive Joins</h2>
    <button class="ghost" id="leaveAll">Alle verlassen</button>
  </div>
  <div class="card" style="padding: 6px 8px;">
    <table>
      <thead>
        <tr><th></th><th>Gruppe</th><th>Source</th><th>Interface</th><th>Port</th>
            <th>Pakete</th><th>Bitrate</th><th>Uptime</th><th></th></tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="empty" id="empty">Keine aktiven Joins</div>
  </div>
</main>
<script>
const $ = id => document.getElementById(id);
let prev = {};   // id -> {bytes, t}

async function api(path, body) {
  const opt = body ? {method: "POST", body: JSON.stringify(body)} : {};
  const r = await fetch(path, opt);
  return r.json();
}

function showErr(text) {
  const m = $("msg");
  m.textContent = text; m.style.display = text ? "block" : "none";
}

async function loadInterfaces() {
  const d = await api("/api/interfaces");
  $("sys").textContent = d.system;
  const sel = $("iface");
  const cur = sel.value;
  sel.innerHTML = "";
  for (const i of d.interfaces) {
    const o = document.createElement("option");
    o.value = i.ip;
    o.dataset.name = i.name;
    o.textContent = `${i.name} — ${i.ip}`;
    sel.appendChild(o);
  }
  if (cur) sel.value = cur;
}

function fmtRate(bps) {
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " Mbit/s";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " kbit/s";
  return bps.toFixed(0) + " bit/s";
}
function fmtUp(s) {
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60;
  return (h ? h + "h " : "") + (m ? m + "m " : "") + sec + "s";
}

async function refresh() {
  const d = await api("/api/joins");
  const rows = $("rows");
  rows.innerHTML = "";
  $("empty").style.display = d.joins.length ? "none" : "block";
  const nprev = {};
  for (const j of d.joins) {
    let rate = null, rx = false;
    const p = prev[j.id];
    if (p && j.port) {
      const dt = d.now - p.t;
      if (dt > 0) rate = Math.max(0, (j.bytes - p.bytes) * 8 / dt);
      rx = j.packets > p.packets;
    }
    nprev[j.id] = {bytes: j.bytes, packets: j.packets, t: d.now};
    const tr = document.createElement("tr");
    const rateCell = j.error ? '<span class="errtext">unterbrochen</span>'
      : rate === null ? '<span class="muted">—</span>'
      : '<span class="rate">' + fmtRate(rate) + "</span>";
    tr.innerHTML = `
      <td><span class="dot ${j.error ? "err" : rx ? "rx" : ""}"></span></td>
      <td>${j.group}</td>
      <td>${j.source || '<span class="muted">*</span>'}</td>
      <td>${j.iface_name} <span class="muted">(${j.iface_ip})</span></td>
      <td>${j.port || '<span class="muted">—</span>'}</td>
      <td>${j.port ? j.packets.toLocaleString() : '<span class="muted">—</span>'}</td>
      <td>${rateCell}</td>
      <td class="muted">${fmtUp(j.uptime)}</td>
      <td></td>`;
    const btn = document.createElement("button");
    btn.className = "leave"; btn.textContent = "Leave";
    btn.onclick = async () => { await api("/api/leave", {id: j.id}); refresh(); };
    tr.lastElementChild.appendChild(btn);
    rows.appendChild(tr);
  }
  prev = nprev;
}

$("joinBtn").onclick = async () => {
  showErr("");
  const sel = $("iface");
  const d = await api("/api/join", {
    group: $("group").value,
    source: $("source").value,
    iface_ip: sel.value,
    iface_name: sel.selectedOptions[0]?.dataset.name || "",
    port: $("port").value,
  });
  if (d.error) { showErr(d.error); return; }
  $("group").value = ""; $("source").value = "";
  refresh();
};
$("leaveAll").onclick = async () => { await api("/api/leave_all"); refresh(); };
for (const id of ["group", "source", "port"])
  $(id).addEventListener("keydown", e => { if (e.key === "Enter") $("joinBtn").click(); });

loadInterfaces();
refresh();
setInterval(refresh, 1000);
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="IGMP Test Tool — multicast subscription GUI")
    ap.add_argument("--port", type=int, default=8688, help="HTTP port for the GUI (default 8688)")
    ap.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    args = ap.parse_args()

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"IGMP Test Tool läuft auf {url}  (Ctrl+C zum Beenden)")
    if not args.no_browser:
        threading.Timer(0.4, webbrowser.open, [url]).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        api_leave_all()
        srv.server_close()


if __name__ == "__main__":
    main()
