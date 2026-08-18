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
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import tempfile
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


# Ports tried when a join is made without a port ("auto-detect"). Always-on
# discovery ports (mDNS 5353, SSDP 1900, WS-Discovery 3702) are left out on
# purpose: their traffic would be attributed to any group.
WELL_KNOWN_PORTS = [5004, 5005, 5006, 5008, 5010, 5012, 5020, 5030, 5040, 5050,
                    5000, 5001, 5002, 5003, 5100, 5200, 319, 320, 2467, 4321,
                    9875, 1234, 1235, 1236, 4000, 4001, 5555, 6000, 8000, 8001,
                    9000, 9001, 9002, 10000, 20000, 30000, 50000, 50004, 50020,
                    14336]
PROBE_SECONDS = 20


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

        self.detect = None        # port auto-detection state (only when no port given)
        self.port_auto = None     # "probe" | "sniff" when the port was detected
        self.detector = None
        self._probes = []
        self.sock = self._make_socket(self.port or 0)
        if self.port:
            self.sock.settimeout(0.5)
            threading.Thread(target=self._recv_loop, daemon=True).start()
        else:
            self._start_probe()

    def _make_socket(self, port):
        """UDP socket bound to the port with the group membership added."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        if SYSTEM == "Windows":
            sock.bind(("", port))
        else:
            # binding to the group filters out unrelated traffic on the port
            try:
                sock.bind((self.group, port))
            except OSError:
                sock.bind(("", port))
        try:
            if self.source:
                sock.setsockopt(socket.IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
                                pack_mreq_source(self.group, self.source, self.iface_ip))
            else:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                pack_mreq(self.group, self.iface_ip))
        except OSError:
            sock.close()
            raise
        return sock

    # -- port auto-detection --------------------------------------------------

    def _start_probe(self):
        """No port given: listen on well-known multicast ports for a while."""
        probes = []
        for p in WELL_KNOWN_PORTS:
            try:
                probes.append((p, self._make_socket(p)))
            except OSError:
                continue
        self._probes = probes
        self.detect = "probing"
        threading.Thread(target=self._probe_loop, daemon=True).start()

    def _probe_loop(self):
        import select
        end = time.time() + PROBE_SECONDS
        by_sock = {s: p for p, s in self._probes}
        while not self._stop.is_set() and time.time() < end and self.port is None:
            try:
                r, _, _ = select.select(list(by_sock), [], [], 0.5)
            except (OSError, ValueError):
                break
            for s in r:
                try:
                    data = s.recv(65536)
                except OSError:
                    continue
                if self.port is None:
                    self._adopt(s, by_sock[s], "probe", first=data)
                    return
        self._close_probes()
        if self.port is None and self.detect == "probing":
            self.detect = "none"

    def _close_probes(self, keep=None):
        for _p, s in self._probes:
            if s is not keep:
                try:
                    s.close()
                except OSError:
                    pass
        self._probes = []

    def _adopt(self, sock, port, how, first=None):
        """Switch to a socket bound to the detected port and start counting."""
        old = self.sock
        self.sock, self.port, self.port_auto, self.detect = sock, port, how, None
        self._close_probes(keep=sock)
        if self.detector:
            self.detector.stop()
            self.detector = None
        if first is not None:
            self.packets += 1
            self.bytes += len(first)
        sock.settimeout(0.5)
        threading.Thread(target=self._recv_loop, daemon=True).start()
        try:
            old.close()   # the new socket already holds the membership -> no IGMP leave
        except OSError:
            pass

    def set_port(self, port, how="sniff"):
        if self.port is not None:
            return
        self._adopt(self._make_socket(port), port, how)

    def start_sniff(self):
        """Accurate detection by capturing UDP traffic to the group (elevated)."""
        if self.port is not None or self.detector:
            return
        self._close_probes()

        def on_port(port, _src):
            try:
                self.set_port(port)
            except OSError:
                pass
        self.detector = PortDetector(self.iface_ip, self.group, on_port)
        self.detect = "sniff"

    def detect_text(self):
        """Human-readable detection state for the UI while no port is known."""
        if self.port is not None:
            return None
        if self.detect == "probing":
            return "auto-detecting (well-known ports) …"
        if self.detect == "sniff" and self.detector:
            kind, msg = self.detector.phase()
            return {"ok": "sniffing traffic for the port …",
                    "wait": "waiting for authorization …"}.get(kind, f"error: {msg}")
        return "no known port seen · use Detect port"

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
        self._close_probes()
        if self.detector:
            self.detector.stop()
            self.detector = None
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
            "port_auto": self.port_auto,
            "detect": self.detect_text(),
        }


# ------------------------------------------------------- querier analysis ---
#
# Capturing IGMP queries needs a raw socket, i.e. root/administrator. If the
# app itself is not privileged, it launches a small *helper* — this same
# script/executable with `--querier-helper` — through the platform's native
# elevation dialog (macOS password prompt, Windows UAC, Linux polkit). The
# helper streams parsed queries back over a loopback TCP connection; the GUI
# process stays unprivileged and only asks once per session.

def _decode_exp(code):
    """IGMPv3 exponential encoding (Max Resp Code / QQIC, values >= 128)."""
    if code < 128:
        return code
    mant = code & 0x0F
    exp = (code >> 4) & 0x07
    return (mant | 0x10) << (exp + 3)


def _ping_once(ip):
    cmd = {"Darwin": ["ping", "-c", "1", "-t", "2", ip],
           "Windows": ["ping", "-n", "1", "-w", "1000", ip]}.get(
        SYSTEM, ["ping", "-c", "1", "-W", "2", ip])
    try:
        subprocess.run(cmd, capture_output=True, timeout=4,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:  # noqa: BLE001
        pass


def _arp_lookup(ip):
    try:
        if SYSTEM == "Windows":
            out = subprocess.check_output(
                ["arp", "-a", ip], text=True, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            m = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out)
            return m.group(1).replace("-", ":").lower() if m else None
        if SYSTEM == "Darwin":
            out = subprocess.check_output(["arp", "-n", ip], text=True, errors="replace")
        else:
            out = subprocess.check_output(["ip", "neigh", "show", ip], text=True, errors="replace")
        m = re.search(r"((?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})", out)
        if not m:
            return None
        # macOS prints single-digit octets ("0:1a:..") — normalize
        return ":".join(f"{int(o, 16):02x}" for o in m.group(1).split(":"))
    except Exception:  # noqa: BLE001
        return None


def _vendor_lookup(mac):
    try:
        import urllib.request
        with urllib.request.urlopen(f"https://api.macvendors.com/{mac}", timeout=4) as r:
            return r.read().decode("utf-8", "replace").strip()
    except Exception:  # noqa: BLE001
        return None


def parse_igmp_query(pkt):
    """Parse a raw IPv4 packet; return an event dict for IGMP membership
    queries, None for anything else."""
    if len(pkt) < 28 or pkt[0] >> 4 != 4 or pkt[9] != 2:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    igmp = pkt[ihl:]
    if len(igmp) < 8 or igmp[0] != 0x11:
        return None
    src = socket.inet_ntoa(pkt[12:16])
    group = socket.inet_ntoa(igmp[4:8])
    if len(igmp) >= 12:
        version = 3
        qqic = _decode_exp(igmp[9]) or None
        max_resp = _decode_exp(igmp[1]) / 10.0
    elif igmp[1] == 0:
        version, qqic, max_resp = 1, None, 10.0  # v1: fixed 10 s
    else:
        version, qqic, max_resp = 2, None, igmp[1] / 10.0
    return {"src": src, "group": group, "version": version,
            "qqic": qqic, "max_resp": max_resp}


def open_igmp_raw_socket(iface_ip):
    """Raw IGMP receive socket — raises PermissionError without privileges."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
    if SYSTEM == "Windows":
        # raw receive on Windows needs a bound socket; RCVALL captures
        # multicast reliably (we filter for IGMP in the parser)
        sock.bind((iface_ip, 0))
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except OSError:
            pass
    sock.settimeout(0.5)
    return sock


class QuerierState:
    """Aggregates query events per querier and resolves MAC/vendor."""

    def __init__(self):
        self.queriers = {}   # src ip -> info dict
        self.lock = threading.Lock()

    def ingest(self, ev):
        now = time.time()
        src, group = ev["src"], ev["group"]
        need_mac = False
        with self.lock:
            q = self.queriers.setdefault(src, {"measured": None, "last_general": None})
            q.update(version=ev["version"], qqic=ev["qqic"],
                     max_resp=ev["max_resp"], last_seen=now)
            if group == "0.0.0.0":  # general query -> measure real interval
                if q["last_general"]:
                    q["measured"] = now - q["last_general"]
                q["last_general"] = now
            if "mac" not in q and src != "0.0.0.0":
                q["mac"] = None  # reserved: only one resolver thread per source
                need_mac = True
        if need_mac:
            threading.Thread(target=self._resolve, args=(src,), daemon=True).start()

    def _resolve(self, ip):
        _ping_once(ip)  # populate the ARP cache
        mac = _arp_lookup(ip)
        vendor = _vendor_lookup(mac) if mac else None
        with self.lock:
            self.queriers[ip]["mac"] = mac
            self.queriers[ip]["vendor"] = vendor

    def status(self):
        now = time.time()
        with self.lock:
            items = [dict(q, ip=ip, ago=now - q["last_seen"])
                     for ip, q in self.queriers.items()]
        items.sort(key=lambda q: socket.inet_aton(q["ip"]))
        if items:
            items[0]["elected"] = True  # lowest IP wins the querier election
        return items


class RawCaptureSource:
    """In-process capture — used when we already have privileges."""

    def __init__(self, iface_ip, state):
        self.sock = open_igmp_raw_socket(iface_ip)
        self.state = state
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                pkt = self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                time.sleep(0.5)
                continue
            try:
                ev = parse_igmp_query(pkt)
                if ev:
                    self.state.ingest(ev)
            except Exception:  # noqa: BLE001
                pass

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def _iface_name_for(ip):
    for e in list_interfaces():
        name, addr = (e["name"], e["ip"]) if isinstance(e, dict) else e
        if addr == ip:
            return name
    return None


def _udp_dst_port(pkt, group):
    """dst UDP port if pkt is an IPv4/UDP datagram addressed to group, else None."""
    if len(pkt) < 28 or pkt[0] >> 4 != 4 or pkt[9] != 17:
        return None
    if socket.inet_ntoa(pkt[16:20]) != group:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < ihl + 4:
        return None
    return int.from_bytes(pkt[ihl + 2:ihl + 4], "big"), socket.inet_ntoa(pkt[12:16])


class PortSniffSource:
    """Privileged capture of UDP traffic to a multicast group; calls
    on_port(port, src) once per newly seen destination port. Windows: raw
    socket with RCVALL; Linux: raw IPPROTO_UDP socket; macOS: raw sockets do
    not see UDP, so tcpdump (always present) is used."""

    def __init__(self, iface_ip, group, on_port):
        self.group, self.on_port = group, on_port
        self.seen = set()
        self._stop = threading.Event()
        self.proc = None
        self.sock = None
        if SYSTEM == "Darwin":
            if os.geteuid() != 0:
                raise PermissionError("capturing UDP needs root")
            name = _iface_name_for(iface_ip)
            if not name:
                raise OSError(f"no interface with address {iface_ip}")
            self.proc = subprocess.Popen(
                ["tcpdump", "-i", name, "-p", "-n", "-l", "-q", "-t", f"udp and dst host {group}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            threading.Thread(target=self._tcpdump_loop, daemon=True).start()
        else:
            if SYSTEM == "Windows":
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((iface_ip, 0))
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            s.settimeout(0.5)
            self.sock = s
            threading.Thread(target=self._raw_loop, daemon=True).start()

    def _report(self, port, src):
        if port not in self.seen:
            self.seen.add(port)
            try:
                self.on_port(port, src)
            except Exception:  # noqa: BLE001
                pass

    def _tcpdump_loop(self):
        pat = re.compile(r"IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > \d+\.\d+\.\d+\.\d+\.(\d+): UDP")
        for line in self.proc.stdout:
            if self._stop.is_set():
                break
            m = pat.search(line)
            if m:
                self._report(int(m.group(3)), m.group(1))

    def _raw_loop(self):
        while not self._stop.is_set():
            try:
                pkt = self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                time.sleep(0.5)
                continue
            r = _udp_dst_port(pkt, self.group)
            if r:
                self._report(*r)

    def stop(self):
        self._stop.set()
        if self.proc:
            try:
                self.proc.terminate()
            except OSError:
                pass
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass



_STAGED = {}
_STAGE_DIRS = []


def _stage_for_root(path):
    """macOS TCC: a root process spawned via osascript may not read files in
    Desktop/Documents/Downloads/iCloud/external volumes. If our program lives
    there, copy it (script or whole .app bundle) to a temp dir once per
    session and run the copy instead."""
    if SYSTEM != "Darwin":
        return path
    home = os.path.expanduser("~")
    protected = [os.path.join(home, d) for d in ("Desktop", "Documents", "Downloads",
                                                   "Library/Mobile Documents")] + ["/Volumes"]
    real = os.path.realpath(path)
    if not any(real.startswith(p + os.sep) for p in protected):
        return path
    if real in _STAGED:
        return _STAGED[real]
    import shutil
    stage = tempfile.mkdtemp(prefix="igmp-test-tool-helper-")
    _STAGE_DIRS.append(stage)
    m = re.match(r"^(.*?\.app)/Contents/MacOS/[^/]+$", real)
    if m:  # frozen .app bundle: copy the bundle, keep the same relative binary path
        bundle = m.group(1)
        dst = os.path.join(stage, os.path.basename(bundle))
        shutil.copytree(bundle, dst, symlinks=True)
        staged = os.path.join(dst, os.path.relpath(real, bundle))
    else:
        staged = os.path.join(stage, os.path.basename(real))
        shutil.copy2(real, staged)
    _STAGED[real] = staged
    return staged


def _helper_command(port, token):
    """argv for launching this program in helper mode."""
    if getattr(sys, "frozen", False):
        return [_stage_for_root(sys.executable), "--querier-helper", str(port), token]
    return [sys.executable, _stage_for_root(os.path.abspath(__file__)),
            "--querier-helper", str(port), token]


class ElevatedHelper:
    """Launches the elevated capture helper once and keeps it for the whole
    session, so the user is asked for credentials only once."""

    _shared = None
    _lock = threading.Lock()

    @classmethod
    def shared(cls):
        with cls._lock:
            if cls._shared is None or cls._shared.dead:
                cls._shared = cls()
            return cls._shared

    def __init__(self):
        self.conn = None
        self.state = None
        self.error = None
        self.dead = False
        self._pending = None
        self.sniff_cbs = {}      # id -> (iface, group, callback)
        self.sniff_errors = {}
        self._proc = None
        self._send_lock = threading.Lock()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(180)
        self.port = self._listener.getsockname()[1]
        import secrets
        self.token = secrets.token_hex(16)
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._launch, daemon=True).start()

    # -- launching via the platform's elevation dialog ------------------------

    def _launch(self):
        cmd = _helper_command(self.port, self.token)
        try:
            if SYSTEM == "Windows":
                import ctypes
                exe, params = cmd[0], subprocess.list2cmdline(cmd[1:])
                rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 0)
                if rc <= 32:
                    self._fail("Elevation cancelled (UAC)" if rc == 5
                               else f"Could not launch elevated helper (code {rc})")
            elif SYSTEM == "Darwin":
                import shlex
                sh = shlex.join(cmd).replace("\\", "\\\\").replace('"', '\\"')
                script = f'do shell script "{sh}" with administrator privileges'
                self._proc = subprocess.Popen(["osascript", "-e", script],
                                              stdout=subprocess.DEVNULL,
                                              stderr=subprocess.PIPE, text=True)
                _out, err = self._proc.communicate()      # blocks while helper runs
                if self._proc.returncode != 0 and self.conn is None:
                    self._fail("Authorization cancelled" if "-128" in (err or "")
                               else f"Could not launch elevated helper: {(err or '').strip()}")
                self._fail("Helper exited")
            else:
                import shutil
                if not shutil.which("pkexec"):
                    self._fail("No graphical elevation available — please run with sudo")
                    return
                self._proc = subprocess.Popen(["pkexec"] + cmd, stdout=subprocess.DEVNULL,
                                              stderr=subprocess.DEVNULL)
                self._proc.wait()
                if self.conn is None:
                    self._fail("Authorization cancelled" if self._proc.returncode in (126, 127)
                               else f"Elevated helper exited (code {self._proc.returncode})")
                self._fail("Helper exited")
        except Exception as exc:  # noqa: BLE001
            self._fail(f"Could not launch elevated helper: {exc}")

    def _fail(self, msg):
        if not self.dead:
            self.error = msg
        self.dead = True
        try:
            self._listener.close()
        except OSError:
            pass
        c, self.conn = self.conn, None
        if c:
            try:
                c.shutdown(socket.SHUT_RDWR)   # makefile() holds a ref; close() alone is silent
            except OSError:
                pass
            try:
                c.close()
            except OSError:
                pass

    # -- connection with the helper -------------------------------------------

    def _accept(self):
        try:
            conn, _ = self._listener.accept()
        except OSError:
            if not self.dead:
                self._fail("Timed out waiting for authorization")
            self._kill_launcher()
            return
        try:
            f = conn.makefile("r", encoding="utf-8")
            hello = json.loads(f.readline() or "{}")
            if hello.get("token") != self.token:
                conn.close()
                self._fail("Helper handshake failed")
                return
            self.conn = conn
            self.error = None
            if self._pending:
                self._send({"cmd": "start", "iface": self._pending})
            for sid, (iface, group, _cb) in list(self.sniff_cbs.items()):
                self._send({"cmd": "sniff", "id": sid, "iface": iface, "group": group})
            for line in f:
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if "sniff" in msg:
                    if "error" in msg:
                        self.sniff_errors[msg["sniff"]] = msg["error"]
                    else:
                        ent = self.sniff_cbs.get(msg["sniff"])
                        if ent:
                            ent[2](msg["port"], msg.get("src"))
                elif "error" in msg:
                    self.error = msg["error"]
                elif "src" in msg and self.state:
                    self.state.ingest(msg)
        except OSError:
            pass
        self._fail("Helper connection lost")

    def _kill_launcher(self):
        p = self._proc
        if p and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass

    def _send(self, obj):
        c = self.conn
        if not c:
            return
        try:
            with self._send_lock:
                c.sendall((json.dumps(obj) + "\n").encode())
        except OSError:
            self._fail("Helper connection lost")

    # -- API used by QuerierMonitor -------------------------------------------

    def start(self, iface_ip, state):
        self.state = state
        self._pending = iface_ip
        self.error = None
        if self.conn:
            self._send({"cmd": "start", "iface": iface_ip})

    def stop_capture(self):
        self._pending = None
        self.state = None
        self._send({"cmd": "stop"})

    def sniff(self, sid, iface_ip, group, cb):
        self.sniff_cbs[sid] = (iface_ip, group, cb)
        self.sniff_errors.pop(sid, None)
        if self.conn:
            self._send({"cmd": "sniff", "id": sid, "iface": iface_ip, "group": group})

    def stop_sniff(self, sid):
        self.sniff_cbs.pop(sid, None)
        self._send({"cmd": "stopsniff", "id": sid})

    def shutdown(self):
        self._fail("closed")
        self._kill_launcher()

    @property
    def connected(self):
        return self.conn is not None


def run_querier_helper(port, token):
    """Entry point of the elevated helper process (`--querier-helper PORT TOKEN`)."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=10)
    conn.settimeout(None)
    lock = threading.Lock()
    alive = threading.Event()
    alive.set()

    def send(obj):
        try:
            with lock:
                conn.sendall((json.dumps(obj) + "\n").encode())
        except OSError:
            alive.clear()

    class _Relay:
        def ingest(self, ev):
            send(ev)

    send({"token": token})
    capture = None
    sniffs = {}

    def heartbeat():   # detects a vanished GUI, then exits
        while alive.is_set():
            time.sleep(2)
            send({"hb": 1})
        os._exit(0)
    threading.Thread(target=heartbeat, daemon=True).start()

    try:
        for line in conn.makefile("r", encoding="utf-8"):
            try:
                cmd = json.loads(line)
            except ValueError:
                continue
            c = cmd.get("cmd")
            if c in ("start", "stop") and capture:
                capture.stop()
                capture = None
            if c == "start":
                try:
                    capture = RawCaptureSource(cmd["iface"], _Relay())
                    send({"started": cmd["iface"]})
                except OSError as exc:
                    send({"error": f"Raw socket failed in elevated helper: {exc}"})
            elif c == "sniff":
                sid = cmd["id"]
                try:
                    sniffs[sid] = PortSniffSource(
                        cmd["iface"], cmd["group"],
                        lambda p, s, sid=sid: send({"sniff": sid, "port": p, "src": s}))
                except OSError as exc:
                    send({"sniff": sid, "error": f"capture failed in elevated helper: {exc}"})
            elif c == "stopsniff":
                sn = sniffs.pop(cmd.get("id"), None)
                if sn:
                    sn.stop()
    except OSError:
        pass
    finally:
        if capture:
            capture.stop()
        for sn in sniffs.values():
            sn.stop()
        os._exit(0)


class QuerierMonitor:
    """Facade: captures in-process when privileged, otherwise via the
    elevated helper. `status()` yields the querier list, `phase()` a
    human-readable state for the UI."""

    def __init__(self, iface_ip):
        self.iface_ip = iface_ip
        self.state = QuerierState()
        self.local = None
        self.helper = None
        try:
            self.local = RawCaptureSource(iface_ip, self.state)
        except OSError:
            self.helper = ElevatedHelper.shared()
            self.helper.start(iface_ip, self.state)

    def status(self):
        return self.state.status()

    def phase(self):
        """('ok'|'wait'|'error', message)"""
        if self.local:
            return "ok", "Capturing (running with privileges)"
        h = self.helper
        if h.error:
            return "error", h.error
        if not h.connected:
            return "wait", ("Waiting for authorization — please confirm the "
                            "system dialog (password / UAC) …")
        return "ok", "Capturing via elevated helper"

    def stop(self):
        if self.local:
            self.local.stop()
        elif self.helper:
            self.helper.stop_capture()

    @staticmethod
    def shutdown_helper():
        h = ElevatedHelper._shared
        if h:
            h.shutdown()
        import shutil
        for d in _STAGE_DIRS:   # remove staged helper copies (macOS TCC workaround)
            shutil.rmtree(d, ignore_errors=True)
        _STAGE_DIRS.clear()
        _STAGED.clear()


QMON = None


def api_querier(body):
    global QMON
    action = body.get("action")
    if action == "stop":
        if QMON:
            QMON.stop()
            QMON = None
        return {"ok": True}
    if action == "start":
        if QMON:
            return {"ok": True}
        iface_ip = (body.get("iface_ip") or "").strip()
        try:
            ipaddress.ip_address(iface_ip)
        except ValueError:
            return {"error": "Please select an interface"}
        QMON = QuerierMonitor(iface_ip)   # asks for privileges via system dialog if needed
        return {"ok": True}
    return {"error": "unknown action"}


class PortDetector:
    """Facade for port sniffing: in-process when privileged, else via the
    elevated helper (same session-wide authorization as the querier)."""

    _next_id = 1
    _lock = threading.Lock()

    def __init__(self, iface_ip, group, on_port):
        self.local = None
        self.helper = None
        with PortDetector._lock:
            self.id = PortDetector._next_id
            PortDetector._next_id += 1
        try:
            self.local = PortSniffSource(iface_ip, group, on_port)
        except OSError:
            self.helper = ElevatedHelper.shared()
            self.helper.sniff(self.id, iface_ip, group, on_port)

    def phase(self):
        if self.local:
            return "ok", "capturing"
        h = self.helper
        err = h.sniff_errors.get(self.id) or h.error
        if err:
            return "error", err
        if not h.connected:
            return "wait", "waiting for authorization"
        return "ok", "capturing via elevated helper"

    def stop(self):
        if self.local:
            self.local.stop()
        elif self.helper:
            self.helper.stop_sniff(self.id)


# ---------------------------------------------------------------- library ---
#
# Every successful join is remembered (group, source, port) so it can be
# re-used later. Stored as JSON in the user's profile; the native app and the
# web GUI share the same file.

def library_path():
    if SYSTEM == "Darwin":
        base = os.path.expanduser("~/Library/Application Support/IGMP Test Tool")
    elif SYSTEM == "Windows":
        base = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "IGMP Test Tool")
    else:
        base = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                            "igmp-test-tool")
    return os.path.join(base, "library.json")


class Library:
    MAX = 200

    def __init__(self, path=None):
        self.path = path or library_path()
        self.lock = threading.Lock()
        self.items = []
        self._load()

    @staticmethod
    def _key(group, source, port):
        return (group, source or "", int(port) if port else None)

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self.items = [i for i in data.get("items", []) if "group" in i]
        except (OSError, ValueError):
            self.items = []

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"items": self.items}, f, indent=1)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def _find(self, group, source, port):
        k = self._key(group, source, port)
        for i in self.items:
            if self._key(i["group"], i.get("source"), i.get("port")) == k:
                return i
        return None

    def remember(self, group, source, port):
        with self.lock:
            self._load()   # pick up changes made by the other variant
            it = self._find(group, source, port)
            if it:
                it["uses"] = it.get("uses", 0) + 1
            else:
                it = {"group": group, "source": source or "", "port": int(port) if port else None,
                      "label": "", "uses": 1}
                self.items.append(it)
            it["last_used"] = time.time()
            self.items.sort(key=lambda i: i.get("last_used", 0), reverse=True)
            del self.items[self.MAX:]
            self._save()

    def remove(self, group, source, port):
        with self.lock:
            self._load()
            it = self._find(group, source, port)
            if it:
                self.items.remove(it)
                self._save()

    def set_label(self, group, source, port, label):
        with self.lock:
            self._load()
            it = self._find(group, source, port)
            if it:
                it["label"] = (label or "").strip()
                self._save()

    def list(self):
        with self.lock:
            self._load()
            return [dict(i) for i in self.items]


LIBRARY = Library()


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
            return {"error": f"{group} is not a multicast address (224.0.0.0/4)"}
    except ValueError:
        return {"error": f"Invalid multicast address: {group!r}"}
    if source:
        try:
            src = ipaddress.ip_address(source)
            if src.is_multicast:
                return {"error": "SSM source must be a unicast address"}
        except ValueError:
            return {"error": f"Invalid source address: {source!r}"}
    try:
        ipaddress.ip_address(iface_ip)
    except ValueError:
        return {"error": "Please select an interface"}
    port = None
    if port_raw not in (None, ""):
        try:
            port = int(port_raw)
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return {"error": f"Invalid port: {port_raw!r}"}

    with JOINS_LOCK:
        for j in JOINS.values():
            if (j.group, j.source or "", j.iface_ip) == (group, source, iface_ip):
                if j.port is None and port:
                    try:
                        j.set_port(port, how=None)   # upgrade the existing join
                    except OSError as exc:
                        return {"error": f"Could not open port {port}: {exc}"}
                    LIBRARY.remove(group, source, None)
                    LIBRARY.remember(group, source, port)
                    return {"ok": True, "join": j.to_dict(),
                            "note": f"Port {port} set on the existing join for {group}."}
                if j.port == port:
                    return {"error": "This join is already active"}
        try:
            j = Join(group, source, iface_ip, iface_name, port)
        except OSError as exc:
            return {"error": f"Join failed: {exc}"}
        JOINS[j.id] = j
    LIBRARY.remember(group, source, port)
    return {"ok": True, "join": j.to_dict()}


def api_detect_port(body):
    with JOINS_LOCK:
        j = JOINS.get(body.get("id"))
    if not j:
        return {"error": "Join not found"}
    if j.port is not None:
        return {"error": f"{j.group} already has port {j.port}"}
    j.start_sniff()
    return {"ok": True}


def _housekeeping():
    """Called on each /api/joins poll: auto-sniff once the helper is authorized,
    move detected ports into the library."""
    helper = ElevatedHelper._shared
    with JOINS_LOCK:
        joins = list(JOINS.values())
    for j in joins:
        if j.port is None:
            if j.detect == "none" and helper and helper.connected and not j.detector:
                j.start_sniff()
        elif j.port_auto and not getattr(j, "_lib_done", False):
            j._lib_done = True
            LIBRARY.remove(j.group, j.source or "", None)
            LIBRARY.remember(j.group, j.source or "", j.port)


def api_library(body):
    action = body.get("action")
    group, source, port = body.get("group"), body.get("source") or "", body.get("port")
    if action == "remove":
        LIBRARY.remove(group, source, port)
    elif action == "label":
        LIBRARY.set_label(group, source, port, body.get("label", ""))
    else:
        return {"error": "unknown action"}
    return {"ok": True, "items": LIBRARY.list()}


def api_leave(body):
    jid = body.get("id")
    with JOINS_LOCK:
        j = JOINS.pop(jid, None)
    if j:
        j.leave()
        return {"ok": True}
    return {"error": "Join not found"}


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
            _housekeeping()
            with JOINS_LOCK:
                self._send_json({"joins": [j.to_dict() for j in JOINS.values()],
                                 "now": time.time()})
        elif self.path == "/api/library":
            self._send_json({"items": LIBRARY.list(), "path": LIBRARY.path})
        elif self.path == "/api/querier":
            if QMON:
                kind, msg = QMON.phase()
                self._send_json({"running": True, "iface": QMON.iface_ip,
                                 "phase": kind, "message": msg,
                                 "queriers": QMON.status()})
            else:
                self._send_json({"running": False, "queriers": []})
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
        elif self.path == "/api/querier":
            self._send_json(api_querier(body))
        elif self.path == "/api/library":
            self._send_json(api_library(body))
        elif self.path == "/api/detect_port":
            self._send_json(api_detect_port(body))
        else:
            self.send_error(404)


INDEX_HTML = r"""<!doctype html>
<html lang="en">
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
    grid-template-columns: 1.2fr 1.1fr 1.6fr .8fr auto;
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
  #msg.note { border-color: var(--border); color: var(--muted); background: transparent; }
  .empty { color: var(--muted); text-align: center; padding: 28px 0; font-size: 14px; }
  tr.lib { cursor: pointer; }
  tr.lib:hover td { background: var(--panel2); }
  button.mini { padding: 4px 10px; font-size: 12.5px; font-weight: 600; }
  .lbl { color: var(--text); font-family: -apple-system, "Segoe UI", system-ui, sans-serif; }
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
        <label><b>Multicast group</b> *</label>
        <input id="group" placeholder="239.1.1.1" spellcheck="false">
      </div>
      <div>
        <label><b>Source</b> (optional, SSM)</label>
        <input id="source" placeholder="e.g. 192.168.10.5" spellcheck="false">
      </div>
      <div>
        <label><b>Interface</b> * <a href="#" id="ifRefresh" title="Refresh interface list" style="color:var(--accent);text-decoration:none;margin-left:6px">⟳ refresh</a></label>
        <select id="iface"></select>
      </div>
      <div>
        <label><b>UDP port</b> (for packet stats)</label>
        <input id="port" placeholder="5004" inputmode="numeric" spellcheck="false">
      </div>
      <div>
        <button id="joinBtn">Join</button>
      </div>
    </div>
    <div id="msg"></div>
    <p class="hint">Without a source an ASM join (IGMPv2/v3) is sent, with a source an SSM join (IGMPv3, INCLUDE).
    With a port the tool counts received packets and shows the bitrate. Without a port it auto-detects well-known ports; "Detect port" captures any port (admin rights via system dialog). The interface list refreshes automatically.</p>
  </div>

  <div class="toolbar">
    <h2>Library — previously joined</h2>
    <span class="muted" style="font-size:12.5px">click a row to fill the form · double-click to join</span>
  </div>
  <div class="card" style="padding: 6px 8px;">
    <table>
      <thead>
        <tr><th>Label</th><th>Group</th><th>Source</th><th>Port</th><th>Last used</th><th>Uses</th><th></th></tr>
      </thead>
      <tbody id="libRows"></tbody>
    </table>
    <div class="empty" id="libEmpty">Every successful join is remembered here automatically.</div>
  </div>

  <div class="toolbar">
    <h2>Querier analysis</h2>
    <button class="ghost" id="qBtn">Start analysis</button>
  </div>
  <div class="card">
    <div id="qBody" class="muted" style="font-family:var(--mono); font-size:13.5px; white-space:pre-wrap; line-height:1.7;">Listens for IGMP queries on the selected interface: querier IP, IGMP version, query interval, MAC + vendor. Elevated rights are requested via the system dialog.</div>
  </div>

  <div class="toolbar">
    <h2>Active joins</h2>
    <button class="ghost" id="leaveAll">Leave all</button>
  </div>
  <div class="card" style="padding: 6px 8px;">
    <table>
      <thead>
        <tr><th></th><th>Group</th><th>Source</th><th>Interface</th><th>Port</th>
            <th>Packets</th><th>Bitrate</th><th>Uptime</th><th></th></tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="empty" id="empty">No active joins</div>
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
  m.className = ""; m.textContent = text; m.style.display = text ? "block" : "none";
}
function showNote(text) {
  const m = $("msg");
  m.className = "note"; m.textContent = text; m.style.display = "block";
}

let ifaceKey = "";
async function loadInterfaces() {
  const d = await api("/api/interfaces");
  $("sys").textContent = d.system;
  const sel = $("iface");
  const key = JSON.stringify(d.interfaces);
  // untouched if nothing changed, or while the user has the dropdown open
  if (key === ifaceKey || (sel.options.length && document.activeElement === sel)) return;
  ifaceKey = key;
  const cur = sel.value;
  sel.innerHTML = "";
  for (const i of d.interfaces) {
    const o = document.createElement("option");
    o.value = i.ip;
    o.dataset.name = i.name;
    o.textContent = `${i.name} — ${i.ip}`;
    sel.appendChild(o);
  }
  if (cur && [...sel.options].some(o => o.value === cur)) sel.value = cur;
}
$("ifRefresh").onclick = async e => {
  e.preventDefault();
  const a = $("ifRefresh"); a.textContent = "⟳ loading …";
  ifaceKey = "";  // force rebuild
  await loadInterfaces();
  a.textContent = "⟳ refresh";
};
setInterval(loadInterfaces, 5000);  // keeps the list current (e.g. USB adapter plugged in)

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
  let d;
  try { d = await api("/api/joins"); } catch (e) { console.warn("joins poll failed", e); return; }
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
    const rateCell = j.error ? '<span class="errtext">interrupted</span>'
      : rate === null ? '<span class="muted">—</span>'
      : '<span class="rate">' + fmtRate(rate) + "</span>";
    tr.innerHTML = `
      <td><span class="dot ${j.error ? "err" : rx ? "rx" : ""}"></span></td>
      <td>${j.group}</td>
      <td>${j.source || '<span class="muted">*</span>'}</td>
      <td>${j.iface_name} <span class="muted">(${j.iface_ip})</span></td>
      <td>${j.port ? j.port + (j.port_auto ? ' <span class="muted">(auto)</span>' : '') : '<span class="muted">—</span>'}</td>
      <td>${j.port ? j.packets.toLocaleString() : '<span class="muted">' + (j.detect || 'set port to count') + '</span>'}</td>
      <td>${rateCell}</td>
      <td class="muted">${fmtUp(j.uptime)}</td>
      <td></td>`;
    if (!j.port) {
      const db = document.createElement("button");
      db.className = "ghost mini"; db.textContent = "Detect port"; db.style.marginRight = "6px";
      db.title = "Capture the UDP port of this group's traffic (asks for admin rights once per session)";
      db.onclick = async () => { const r = await api("/api/detect_port", {id: j.id}); if (r.error) showErr(r.error); refresh(); };
      tr.lastElementChild.appendChild(db);
    }
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
  if (d.note) showNote(d.note);
  else if (!d.join.port) showNote(`Joined ${d.join.group}: no UDP port given, auto-detecting on well-known ports. For any other port use "Detect port" (asks for admin rights) or enter the port and join again.`);
  $("group").value = ""; $("source").value = "";
  refresh(); loadLibrary();
};

function fmtDate(t) {
  const d = new Date(t * 1000), p = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function fillForm(e) {
  $("group").value = e.group; $("source").value = e.source || ""; $("port").value = e.port || "";
}
async function libAction(action, e, extra) {
  const d = await api("/api/library", Object.assign({action, group: e.group, source: e.source, port: e.port}, extra || {}));
  if (d.items) renderLibrary(d.items);
}
function renderLibrary(items) {
  const rows = $("libRows"); rows.innerHTML = "";
  $("libEmpty").style.display = items.length ? "none" : "block";
  for (const e of items) {
    const tr = document.createElement("tr"); tr.className = "lib";
    tr.innerHTML = `
      <td class="lbl">${e.label ? escapeHtml(e.label) : '<span class="muted">—</span>'}</td>
      <td>${e.group}</td>
      <td>${e.source || '<span class="muted">*</span>'}</td>
      <td>${e.port || '<span class="muted">—</span>'}</td>
      <td class="muted">${fmtDate(e.last_used || 0)}</td>
      <td class="muted">${e.uses || 1}</td>
      <td style="white-space:nowrap;text-align:right"></td>`;
    tr.onclick = () => fillForm(e);
    tr.ondblclick = () => { fillForm(e); $("joinBtn").click(); };
    const cell = tr.lastElementChild;
    const mk = (txt, cls, fn) => { const b = document.createElement("button"); b.className = cls;
      b.textContent = txt; b.onclick = ev => { ev.stopPropagation(); fn(); }; cell.appendChild(b); return b; };
    mk("Join", "mini", () => { fillForm(e); $("joinBtn").click(); }).style.marginRight = "6px";
    mk("Label", "ghost mini", () => { const l = prompt("Label for " + e.group + (e.source ? " / " + e.source : ""), e.label || "");
      if (l !== null) libAction("label", e, {label: l}); }).style.marginRight = "6px";
    mk("Remove", "leave mini", () => libAction("remove", e));
    rows.appendChild(tr);
  }
}
function escapeHtml(s) { return s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
async function loadLibrary() { const d = await api("/api/library"); renderLibrary(d.items || []); }
loadLibrary();
setInterval(loadLibrary, 10000);  // picks up changes made in the native app
$("leaveAll").onclick = async () => { await api("/api/leave_all"); refresh(); };

let qRunning = false;
$("qBtn").onclick = async () => {
  if (qRunning) {
    await api("/api/querier", {action: "stop"});
    $("qBody").textContent = "Analysis stopped.";
  } else {
    const d = await api("/api/querier", {action: "start", iface_ip: $("iface").value});
    if (d.error) { $("qBody").textContent = d.error; return; }
    $("qBody").textContent = "Starting …";
  }
  pollQuerier();
};

async function pollQuerier() {
  const d = await api("/api/querier");
  qRunning = d.running;
  $("qBtn").textContent = qRunning ? "Stop analysis" : "Start analysis";
  if (!qRunning) return;
  if (!d.queriers.length) {
    const pre = d.phase === "error" ? "Error: " : "";
    const tail = d.phase === "ok" ? " — waiting for IGMP queries … (general queries typically arrive every 60–125 s)"
               : d.phase === "error" ? "\nFallback: start the server with sudo / as administrator." : "";
    $("qBody").textContent = pre + d.message + tail;
    return;
  }
  $("qBody").innerHTML = d.queriers.map(q => {
    const iv = [q.qqic ? q.qqic + " s (QQIC)" : null,
                q.measured ? q.measured.toFixed(1) + " s measured" : null]
               .filter(Boolean).join(" / ") || "not yet known";
    let mac;
    if (q.ip === "0.0.0.0") mac = "not resolvable (proxy query with source 0.0.0.0)";
    else if (q.mac) mac = `${q.mac} — ${q.vendor || "vendor not resolvable"}`;
    else mac = "resolving …";
    const el = q.elected && d.queriers.length > 1 ? ' <span class="rate">← active (lowest IP)</span>' : "";
    return `<b style="color:var(--text)">Querier ${q.ip}</b>  (IGMPv${q.version})${el}
  Query interval: ${iv} · Max Resp: ${q.max_resp.toFixed(1)} s · last seen ${q.ago.toFixed(0)} s ago
  MAC: ${mac}`;
  }).join("\n\n");
}
setInterval(pollQuerier, 2000);
pollQuerier();
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
    if len(sys.argv) >= 4 and sys.argv[1] == "--querier-helper":
        run_querier_helper(int(sys.argv[2]), sys.argv[3])   # elevated capture helper
        return
    ap = argparse.ArgumentParser(description="IGMP Test Tool — multicast subscription GUI")
    ap.add_argument("--port", type=int, default=8688, help="HTTP port for the GUI (default 8688)")
    ap.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    args = ap.parse_args()

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"IGMP Test Tool running at {url}  (Ctrl+C to quit)")
    if not args.no_browser:
        threading.Timer(0.4, webbrowser.open, [url]).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        api_leave_all()
        QuerierMonitor.shutdown_helper()
        srv.server_close()


if __name__ == "__main__":
    main()
