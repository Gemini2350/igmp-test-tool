#!/usr/bin/env python3
"""IGMP Test Tool — native GUI (Tkinter), cross-platform.

Join multicast groups (ASM or SSM) on a selected interface, with live
receive statistics. Single file, stdlib only.

Run directly:      python3 igmp_join_gui.py
Build executable:  pyinstaller --onefile --windowed --name "IGMP Test Tool" igmp_join_gui.py
"""

import faulthandler
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import tkinter as tk
from tkinter import ttk

SYSTEM = platform.system()

# Unhandled errors land here instead of killing the windowed app silently
# (PyInstaller --windowed has no console).
CRASH_LOG = os.path.join(tempfile.gettempdir(), "igmp-test-tool-crash.log")


def _log_crash(kind, exc_type, exc_value, exc_tb):
    try:
        with open(CRASH_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} [{kind}] ---\n")
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    except Exception:  # noqa: BLE001
        pass


sys.excepthook = lambda t, v, tb: _log_crash("main", t, v, tb)
threading.excepthook = lambda a: _log_crash("thread", a.exc_type, a.exc_value, a.exc_traceback)
try:
    _fh_file = open(CRASH_LOG, "a")  # keep open for faulthandler (native crashes)
    faulthandler.enable(_fh_file)
except OSError:
    pass

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
    return socket.inet_aton(group) + socket.inet_aton(iface)


def pack_mreq_source(group, source, iface):
    g, s, i = (socket.inet_aton(x) for x in (group, source, iface))
    if SYSTEM == "Linux":
        return g + i + s  # imr_multiaddr, imr_interface, imr_sourceaddr
    return g + s + i      # imr_multiaddr, imr_sourceaddr, imr_interface


def list_interfaces():
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
                    ifaces.append((cur, m.group(1)))
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
                ifaces.append((e["InterfaceAlias"], e["IPAddress"]))
        else:  # Linux
            out = subprocess.check_output(["ip", "-j", "-4", "addr", "show"], text=True)
            for e in json.loads(out):
                for a in e.get("addr_info", []):
                    if a.get("family") == "inet":
                        ifaces.append((e["ifname"], a["local"]))
    except Exception as exc:  # noqa: BLE001
        print(f"interface enumeration failed: {exc}", file=sys.stderr)
    ifaces.sort(key=lambda i: i[1].startswith("127."))
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
    def __init__(self, group, source, iface_ip, iface_name, port):
        self.group = group
        self.source = source or None
        self.iface_ip = iface_ip
        self.iface_name = iface_name
        self.port = port or None
        self.started = time.time()
        self.packets = 0
        self.bytes = 0
        self.error = False
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
                self.error = False
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                self.error = True
                self._stop.wait(1.0)
                self._try_rejoin()
            except Exception:  # noqa: BLE001
                if self._stop.is_set():
                    break
                self.error = True
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
            self.error = False
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


def fmt_rate(bps):
    if bps >= 1e6:
        return f"{bps / 1e6:.2f} Mbit/s"
    if bps >= 1e3:
        return f"{bps / 1e3:.1f} kbit/s"
    return f"{bps:.0f} bit/s"


def fmt_uptime(s):
    s = int(s)
    h, m, sec = s // 3600, s % 3600 // 60, s % 60
    return (f"{h}h " if h else "") + (f"{m}m " if m or h else "") + f"{sec}s"


class App:
    def __init__(self, root):
        self.root = root
        root.title("IGMP Test Tool")
        root.minsize(900, 600)
        self.joins = {}       # tree item id -> Join
        self.prev = {}        # tree item id -> (bytes, packets, t)
        self.ifaces = []
        self._iface_scan = None   # result of background interface scan

        pad = {"padx": 6, "pady": 4}
        form = ttk.LabelFrame(root, text=" New join ")
        form.pack(fill="x", padx=12, pady=(12, 6))

        ttk.Label(form, text="Multicast group *").grid(row=0, column=0, sticky="w", **pad)
        ttk.Label(form, text="Source (optional, SSM)").grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(form, text="Interface *").grid(row=0, column=2, sticky="w", **pad)
        ttk.Label(form, text="UDP port (for packet stats)").grid(row=0, column=3, sticky="w", **pad)

        self.e_group = ttk.Entry(form, width=18)
        self.e_group.grid(row=1, column=0, sticky="we", **pad)
        self.e_source = ttk.Entry(form, width=18)
        self.e_source.grid(row=1, column=1, sticky="we", **pad)
        # interface dropdown with a compact refresh button glued to its right;
        # the list also refreshes itself in the background every few seconds
        ifrow = ttk.Frame(form)
        ifrow.grid(row=1, column=2, sticky="we", **pad)
        ifrow.columnconfigure(0, weight=1)
        self.c_iface = ttk.Combobox(ifrow, state="readonly", width=26)
        self.c_iface.grid(row=0, column=0, sticky="we")
        ttk.Button(ifrow, text="⟳", width=2, command=self.load_interfaces)\
            .grid(row=0, column=1, padx=(3, 0))
        self.e_port = ttk.Entry(form, width=10)
        self.e_port.grid(row=1, column=3, sticky="we", **pad)
        btn = ttk.Button(form, text="Join", command=self.do_join, default="active")
        btn.grid(row=1, column=4, sticky="we", **pad)

        for col in range(3):
            form.columnconfigure(col, weight=1)

        self.err = tk.StringVar()
        self.lbl_err = ttk.Label(form, textvariable=self.err, foreground="#c62828")
        self.lbl_err.grid(row=2, column=0, columnspan=6, sticky="w", padx=6)
        ttk.Label(form, foreground="#777", text=(
            "Without source: ASM join (IGMPv2/v3) · with source: SSM join (IGMPv3). "
            "With a UDP port, received packets and bitrate are shown. "
            "Interface list refreshes automatically."
        )).grid(row=3, column=0, columnspan=6, sticky="w", padx=6, pady=(0, 6))

        # -- library: previously joined groups/sources, shared with the web GUI
        lf = ttk.LabelFrame(root, text=" Library — previously joined (double-click to join) ")
        lf.pack(fill="x", padx=12, pady=(0, 4))
        lcols = ("label", "group", "source", "port", "last", "uses")
        self.lib = ttk.Treeview(lf, columns=lcols, show="headings", height=4, selectmode="browse")
        for c, txt, w, st in (("label", "Label", 150, True), ("group", "Group", 130, False),
                              ("source", "Source", 130, False), ("port", "Port", 60, False),
                              ("last", "Last used", 130, False), ("uses", "Uses", 50, False)):
            self.lib.heading(c, text=txt)
            self.lib.column(c, width=w, stretch=st, anchor="w")
        lsb = ttk.Scrollbar(lf, orient="vertical", command=self.lib.yview)
        self.lib.configure(yscrollcommand=lsb.set)
        self.lib.grid(row=0, column=0, sticky="nsew", padx=(6, 0), pady=(4, 2))
        lsb.grid(row=0, column=1, sticky="ns", padx=(0, 6), pady=(4, 2))
        lbar = ttk.Frame(lf)
        lbar.grid(row=1, column=0, columnspan=2, sticky="we", padx=6, pady=(0, 6))
        ttk.Button(lbar, text="Join", command=self.lib_join).pack(side="left")
        ttk.Button(lbar, text="Fill form", command=self.lib_fill).pack(side="left", padx=6)
        ttk.Label(lbar, text="Label:").pack(side="left", padx=(12, 2))
        self.e_label = ttk.Entry(lbar, width=18)
        self.e_label.pack(side="left")
        ttk.Button(lbar, text="Set", width=4, command=self.lib_set_label).pack(side="left", padx=(3, 0))
        ttk.Button(lbar, text="Remove", command=self.lib_remove).pack(side="right")
        self.lib_empty = ttk.Label(lbar, foreground="#777",
                                   text="Every successful join is remembered here automatically.")
        self.lib_empty.pack(side="right", padx=8)
        lf.columnconfigure(0, weight=1)
        self.lib.bind("<Double-1>", lambda _e: self.lib_join())
        self.lib.bind("<<TreeviewSelect>>", self._lib_selected)
        self.lib_items = {}   # tree item id -> library entry
        self.reload_library()

        qf = ttk.LabelFrame(root, text=" Querier analysis ")
        qf.pack(fill="x", padx=12, pady=(0, 4))
        qtop = ttk.Frame(qf)
        qtop.pack(fill="x", padx=6, pady=(4, 0))
        self.q_btn = ttk.Button(qtop, text="Start analysis", command=self.toggle_querier)
        self.q_btn.pack(side="left")
        self.qmon = None
        self.q_text = tk.StringVar(value=(
            "Listens for IGMP queries on the selected interface: querier IP, IGMP version, "
            "query interval, MAC + vendor. Elevated rights are requested via the system dialog."))
        ttk.Label(qf, textvariable=self.q_text, justify="left",
                  font=("Courier" if SYSTEM == "Windows" else "Menlo", 12)
                  ).pack(fill="x", padx=8, pady=(4, 8))

        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=12, pady=(6, 0))
        ttk.Label(bar, text="Active joins").pack(side="left")
        ttk.Button(bar, text="Leave all", command=self.leave_all).pack(side="right")
        ttk.Button(bar, text="Leave selected", command=self.leave_selected).pack(side="right", padx=6)
        ttk.Button(bar, text="Detect port", command=self.detect_port).pack(side="right")

        cols = ("rx", "group", "source", "iface", "port", "pkts", "rate", "up")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="browse")
        headings = {"rx": "", "group": "Group", "source": "Source", "iface": "Interface",
                    "port": "Port", "pkts": "Packets", "rate": "Bitrate", "up": "Uptime"}
        widths = {"rx": 30, "group": 130, "source": 130, "iface": 190,
                  "port": 90, "pkts": 200, "rate": 110, "up": 80}
        for c in cols:
            self.tree.heading(c, text=headings[c])
            anchor = "center" if c == "rx" else "w"
            self.tree.column(c, width=widths[c], anchor=anchor,
                             stretch=c in ("iface", "group", "source"))
        self.tree.tag_configure("rx", foreground="#2e7d32")
        self.tree.tag_configure("idle", foreground="#999")
        self.tree.tag_configure("err", foreground="#c62828")
        self.tree.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        self.load_interfaces()
        for w in (self.e_group, self.e_source, self.e_port):
            w.bind("<Return>", lambda _e: self.do_join())
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(1000, self.tick)
        threading.Thread(target=self._iface_scan_loop, daemon=True).start()

    # -- interfaces -----------------------------------------------------------

    def _apply_interfaces(self, ifaces):
        cur = self.c_iface.get()
        self.ifaces = ifaces
        vals = [f"{n} — {ip}" for n, ip in ifaces]
        self.c_iface["values"] = vals
        if cur in vals:
            self.c_iface.set(cur)       # keep selection if still present
        elif vals:
            self.c_iface.current(0)     # otherwise fall back to first
        else:
            self.c_iface.set("")

    def load_interfaces(self):
        """Explicit refresh (button / startup): synchronous."""
        self._apply_interfaces(list_interfaces())

    def _iface_scan_loop(self):
        """Background scan every 5 s; UI is only touched when the list changed."""
        while True:
            time.sleep(5)
            try:
                found = list_interfaces()
            except Exception:  # noqa: BLE001
                continue
            if found != self.ifaces:
                self.root.after(0, self._apply_interfaces, found)

    # -- joins ----------------------------------------------------------------

    def do_join(self):
        self.err.set("")
        self.lbl_err.configure(foreground="#c62828")
        group = self.e_group.get().strip()
        source = self.e_source.get().strip()
        port_raw = self.e_port.get().strip()
        idx = self.c_iface.current()

        try:
            if not ipaddress.ip_address(group).is_multicast:
                self.err.set(f"{group} is not a multicast address (224.0.0.0/4)")
                return
        except ValueError:
            self.err.set(f"Invalid multicast address: {group!r}")
            return
        if source:
            try:
                if ipaddress.ip_address(source).is_multicast:
                    self.err.set("SSM source must be a unicast address")
                    return
            except ValueError:
                self.err.set(f"Invalid source address: {source!r}")
                return
        if idx < 0 or idx >= len(self.ifaces):
            self.err.set("Please select an interface")
            return
        iface_name, iface_ip = self.ifaces[idx]
        port = None
        if port_raw:
            try:
                port = int(port_raw)
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                self.err.set(f"Invalid port: {port_raw!r}")
                return
        for j in self.joins.values():
            if (j.group, j.source or "", j.iface_ip) == (group, source, iface_ip):
                if j.port is None and port:
                    try:
                        j.set_port(port, how=None)   # upgrade the existing join
                    except OSError as exc:
                        self.err.set(f"Could not open port {port}: {exc}")
                        return
                    self.lbl_err.configure(foreground="#777")
                    self.err.set(f"Port {port} set on the existing join for {group}.")
                    self.e_group.delete(0, "end")
                    self.e_source.delete(0, "end")
                    return
                if j.port == port:
                    self.err.set("This join is already active")
                    return
        try:
            j = Join(group, source, iface_ip, iface_name, port)
        except OSError as exc:
            self.err.set(f"Join failed: {exc}")
            return
        item = self.tree.insert("", "end", values=(
            "●", group, source or "*", f"{iface_name} ({iface_ip})",
            port or "—", "—", "—", "0s"), tags=("idle",))
        self.joins[item] = j
        if not port:
            self.lbl_err.configure(foreground="#777")
            self.err.set(f"Joined {group}: no UDP port given, auto-detecting on well-known "
                         "ports. For any other port use 'Detect port' (asks for admin rights) "
                         "or enter the port and join again.")
        else:
            self.lbl_err.configure(foreground="#c62828")
        self.e_group.delete(0, "end")
        self.e_source.delete(0, "end")
        LIBRARY.remember(group, source, port)
        self.reload_library()

    # -- library --------------------------------------------------------------

    def reload_library(self):
        sel = self._lib_current()
        self.lib.delete(*self.lib.get_children())
        self.lib_items.clear()
        entries = LIBRARY.list()
        for e in entries:
            last = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("last_used", 0)))
            iid = self.lib.insert("", "end", values=(
                e.get("label") or "", e["group"], e.get("source") or "*",
                e.get("port") or "—", last, e.get("uses", 1)))
            self.lib_items[iid] = e
            if sel and (e["group"], e.get("source") or "", e.get("port")) == sel:
                self.lib.selection_set(iid)
        if entries:
            self.lib_empty.pack_forget()
        else:
            self.lib_empty.pack(side="right", padx=8)

    def _lib_current(self):
        sel = self.lib.selection()
        if not sel:
            return None
        e = self.lib_items.get(sel[0])
        return (e["group"], e.get("source") or "", e.get("port")) if e else None

    def _lib_selected(self, _e=None):
        sel = self.lib.selection()
        if sel and sel[0] in self.lib_items:
            self.e_label.delete(0, "end")
            self.e_label.insert(0, self.lib_items[sel[0]].get("label") or "")

    def lib_fill(self):
        cur = self._lib_current()
        if not cur:
            return
        group, source, port = cur
        for w, v in ((self.e_group, group), (self.e_source, source),
                     (self.e_port, port or "")):
            w.delete(0, "end")
            w.insert(0, str(v))

    def lib_join(self):
        if not self._lib_current():
            return
        self.lib_fill()
        self.do_join()

    def lib_set_label(self):
        cur = self._lib_current()
        if cur:
            LIBRARY.set_label(*cur, self.e_label.get())
            self.reload_library()

    def lib_remove(self):
        cur = self._lib_current()
        if cur:
            LIBRARY.remove(*cur)
            self.reload_library()

    def detect_port(self):
        """Sniff the UDP port for the selected (port-less) join — needs elevated rights."""
        sel = self.tree.selection()
        cands = [self.joins[i] for i in sel if i in self.joins] or \
                [j for j in self.joins.values() if j.port is None]
        if not cands:
            self.err.set("Select a join without a port (or join a group without a port first).")
            return
        j = cands[0]
        if j.port is not None:
            self.lbl_err.configure(foreground="#777")
            self.err.set(f"{j.group} already has port {j.port}.")
            return
        j.start_sniff()

    def leave_selected(self):
        sel = self.tree.selection()
        for item in sel:
            j = self.joins.pop(item, None)
            if j:
                j.leave()
            self.tree.delete(item)
            self.prev.pop(item, None)

    def leave_all(self):
        for item, j in list(self.joins.items()):
            j.leave()
            self.tree.delete(item)
        self.joins.clear()
        self.prev.clear()

    # -- querier --------------------------------------------------------------

    def toggle_querier(self):
        if self.qmon:
            self.qmon.stop()
            self.qmon = None
            self.q_btn.configure(text="Start analysis")
            self.q_text.set("Analysis stopped.")
            return
        idx = self.c_iface.current()
        if idx < 0 or idx >= len(self.ifaces):
            self.q_text.set("Please select an interface.")
            return
        _name, ip = self.ifaces[idx]
        self.qmon = QuerierMonitor(ip)   # asks for privileges via system dialog if needed
        self.q_btn.configure(text="Stop analysis")
        self._show_phase()

    def _show_phase(self):
        kind, msg = self.qmon.phase()
        if kind == "ok":
            self.q_text.set(f"{msg} — waiting for IGMP queries … "
                            "(general queries typically arrive every 60–125 s)")
        elif kind == "wait":
            self.q_text.set(msg)
        else:
            self.q_text.set(f"Error: {msg}\nFallback: run the app with elevated rights "
                            "(macOS: sudo …/Contents/MacOS/\"IGMP Test Tool\", "
                            "Windows: 'Run as administrator').")

    @staticmethod
    def _format_queriers(qs):
        lines = []
        for q in qs:
            head = f"Querier {q['ip']}  (IGMPv{q['version']})"
            if q.get("elected") and len(qs) > 1:
                head += "  ← active (lowest IP wins the election)"
            iv = []
            if q.get("qqic"):
                iv.append(f"{q['qqic']} s (QQIC)")
            if q.get("measured"):
                iv.append(f"{q['measured']:.1f} s measured")
            lines.append(head)
            lines.append(f"  Query interval: {' / '.join(iv) if iv else 'not yet known'}"
                         f" · Max Resp: {q['max_resp']:.1f} s · last seen {q['ago']:.0f} s ago")
            if q["ip"] == "0.0.0.0":
                mac_s = "not resolvable (proxy query with source 0.0.0.0)"
            elif q.get("mac"):
                mac_s = f"{q['mac']} — {q.get('vendor') or 'vendor not resolvable'}"
            else:
                mac_s = "resolving …"
            lines.append(f"  MAC: {mac_s}")
        return "\n".join(lines)

    # -- periodic UI update ---------------------------------------------------

    def tick(self):
        try:
            now = time.time()
            helper = ElevatedHelper._shared
            for item, j in self.joins.items():
                rate_s, pkts_s, rx = "—", "set port to count", False
                if j.port is None:
                    if j.detect == "none" and helper and helper.connected and not j.detector:
                        j.start_sniff()      # already authorized this session -> just do it
                    pkts_s = j.detect_text()
                elif j.port_auto and not getattr(j, "_lib_done", False):
                    j._lib_done = True       # detected port -> library entry gets the port
                    LIBRARY.remove(j.group, j.source or "", None)
                    LIBRARY.remember(j.group, j.source or "", j.port)
                    self.reload_library()
                if j.port:
                    pkts_s = f"{j.packets:,}"
                    p = self.prev.get(item)
                    if p:
                        dt = now - p[2]
                        if dt > 0:
                            rate_s = fmt_rate(max(0, (j.bytes - p[0]) * 8 / dt))
                        rx = j.packets > p[1]
                    self.prev[item] = (j.bytes, j.packets, now)
                if j.error:
                    tag, rate_s = "err", "interrupted"
                else:
                    tag = "rx" if rx else "idle"
                port_s = f"{j.port} (auto)" if j.port and j.port_auto else (j.port or "—")
                self.tree.item(item, values=(
                    "●", j.group, j.source or "*", f"{j.iface_name} ({j.iface_ip})",
                    port_s, pkts_s, rate_s, fmt_uptime(now - j.started)),
                    tags=(tag,))
            if self.qmon:
                qs = self.qmon.status()
                if qs:
                    self.q_text.set(self._format_queriers(qs))
                else:
                    self._show_phase()
        except Exception:  # noqa: BLE001
            _log_crash("tick", *sys.exc_info())
        self.root.after(1000, self.tick)

    def on_close(self):
        if self.qmon:
            self.qmon.stop()
        QuerierMonitor.shutdown_helper()
        for j in self.joins.values():
            j.leave()
        self.root.destroy()


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "--querier-helper":
        run_querier_helper(int(sys.argv[2]), sys.argv[3])   # elevated capture helper
        return
    root = tk.Tk()
    root.report_callback_exception = lambda t, v, tb: _log_crash("tk", t, v, tb)
    try:
        ttk.Style().theme_use({"Darwin": "aqua", "Windows": "vista"}.get(SYSTEM, "clam"))
    except tk.TclError:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
