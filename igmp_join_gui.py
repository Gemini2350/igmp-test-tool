#!/usr/bin/env python3
"""IGMP Test Tool — native GUI (Tkinter), cross-platform.

Join multicast groups (ASM or SSM) on a selected interface, with live
receive statistics. Single file, stdlib only.

Run directly:      python3 igmp_join_gui.py
Build executable:  pyinstaller --onefile --windowed --name "IGMP Test Tool" igmp_join_gui.py
"""

import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

SYSTEM = platform.system()

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
            threading.Thread(target=self._recv_loop, daemon=True).start()

    def _recv_loop(self):
        while not self._stop.is_set():
            try:
                data = self.sock.recv(65536)
                self.packets += 1
                self.bytes += len(data)
            except socket.timeout:
                continue
            except OSError:
                break

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
        root.minsize(880, 420)
        self.joins = {}       # tree item id -> Join
        self.prev = {}        # tree item id -> (bytes, packets, t)
        self.ifaces = []

        pad = {"padx": 6, "pady": 4}
        form = ttk.LabelFrame(root, text=" Neuer Join ")
        form.pack(fill="x", padx=12, pady=(12, 6))

        ttk.Label(form, text="Multicast-Gruppe *").grid(row=0, column=0, sticky="w", **pad)
        ttk.Label(form, text="Source (optional, SSM)").grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(form, text="Interface *").grid(row=0, column=2, sticky="w", **pad)
        ttk.Label(form, text="UDP-Port (optional)").grid(row=0, column=3, sticky="w", **pad)

        self.e_group = ttk.Entry(form, width=18)
        self.e_group.grid(row=1, column=0, sticky="we", **pad)
        self.e_source = ttk.Entry(form, width=18)
        self.e_source.grid(row=1, column=1, sticky="we", **pad)
        self.c_iface = ttk.Combobox(form, state="readonly", width=28)
        self.c_iface.grid(row=1, column=2, sticky="we", **pad)
        self.e_port = ttk.Entry(form, width=10)
        self.e_port.grid(row=1, column=3, sticky="we", **pad)
        btn = ttk.Button(form, text="Join", command=self.do_join, default="active")
        btn.grid(row=1, column=4, sticky="we", **pad)
        ttk.Button(form, text="⟳", width=3, command=self.load_interfaces)\
            .grid(row=1, column=5, sticky="w", padx=(0, 6))

        for col in range(3):
            form.columnconfigure(col, weight=1)

        self.err = tk.StringVar()
        self.lbl_err = ttk.Label(form, textvariable=self.err, foreground="#c62828")
        self.lbl_err.grid(row=2, column=0, columnspan=6, sticky="w", padx=6)
        ttk.Label(form, foreground="#777", text=(
            "Ohne Source: ASM-Join (IGMPv2/v3) · mit Source: SSM-Join (IGMPv3). "
            "Mit UDP-Port werden empfangene Pakete und Bitrate angezeigt."
        )).grid(row=3, column=0, columnspan=6, sticky="w", padx=6, pady=(0, 6))

        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=12, pady=(6, 0))
        ttk.Label(bar, text="Aktive Joins").pack(side="left")
        ttk.Button(bar, text="Alle verlassen", command=self.leave_all).pack(side="right")
        ttk.Button(bar, text="Leave (Auswahl)", command=self.leave_selected).pack(side="right", padx=6)

        cols = ("rx", "group", "source", "iface", "port", "pkts", "rate", "up")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="browse")
        headings = {"rx": "", "group": "Gruppe", "source": "Source", "iface": "Interface",
                    "port": "Port", "pkts": "Pakete", "rate": "Bitrate", "up": "Uptime"}
        widths = {"rx": 30, "group": 130, "source": 130, "iface": 190,
                  "port": 60, "pkts": 90, "rate": 110, "up": 80}
        for c in cols:
            self.tree.heading(c, text=headings[c])
            anchor = "center" if c == "rx" else "w"
            self.tree.column(c, width=widths[c], anchor=anchor,
                             stretch=c in ("iface", "group", "source"))
        self.tree.tag_configure("rx", foreground="#2e7d32")
        self.tree.tag_configure("idle", foreground="#999")
        self.tree.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        self.load_interfaces()
        for w in (self.e_group, self.e_source, self.e_port):
            w.bind("<Return>", lambda _e: self.do_join())
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(1000, self.tick)

    def load_interfaces(self):
        self.ifaces = list_interfaces()
        vals = [f"{n} — {ip}" for n, ip in self.ifaces]
        self.c_iface["values"] = vals
        if vals and not self.c_iface.get():
            self.c_iface.current(0)

    def do_join(self):
        self.err.set("")
        group = self.e_group.get().strip()
        source = self.e_source.get().strip()
        port_raw = self.e_port.get().strip()
        idx = self.c_iface.current()

        try:
            if not ipaddress.ip_address(group).is_multicast:
                self.err.set(f"{group} ist keine Multicast-Adresse (224.0.0.0/4)")
                return
        except ValueError:
            self.err.set(f"Ungültige Multicast-Adresse: {group!r}")
            return
        if source:
            try:
                if ipaddress.ip_address(source).is_multicast:
                    self.err.set("SSM-Source muss eine Unicast-Adresse sein")
                    return
            except ValueError:
                self.err.set(f"Ungültige Source-Adresse: {source!r}")
                return
        if idx < 0 or idx >= len(self.ifaces):
            self.err.set("Bitte ein Interface auswählen")
            return
        iface_name, iface_ip = self.ifaces[idx]
        port = None
        if port_raw:
            try:
                port = int(port_raw)
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                self.err.set(f"Ungültiger Port: {port_raw!r}")
                return
        for j in self.joins.values():
            if (j.group, j.source or "", j.iface_ip) == (group, source, iface_ip):
                self.err.set("Dieser Join ist bereits aktiv")
                return
        try:
            j = Join(group, source, iface_ip, iface_name, port)
        except OSError as exc:
            self.err.set(f"Join fehlgeschlagen: {exc}")
            return
        item = self.tree.insert("", "end", values=(
            "●", group, source or "*", f"{iface_name} ({iface_ip})",
            port or "—", "—", "—", "0s"), tags=("idle",))
        self.joins[item] = j
        self.e_group.delete(0, "end")
        self.e_source.delete(0, "end")

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

    def tick(self):
        now = time.time()
        for item, j in self.joins.items():
            rate_s, pkts_s, rx = "—", "—", False
            if j.port:
                pkts_s = f"{j.packets:,}".replace(",", "'")
                p = self.prev.get(item)
                if p:
                    dt = now - p[2]
                    if dt > 0:
                        rate_s = fmt_rate(max(0, (j.bytes - p[0]) * 8 / dt))
                    rx = j.packets > p[1]
                self.prev[item] = (j.bytes, j.packets, now)
            self.tree.item(item, values=(
                "●", j.group, j.source or "*", f"{j.iface_name} ({j.iface_ip})",
                j.port or "—", pkts_s, rate_s, fmt_uptime(now - j.started)),
                tags=("rx" if rx else "idle",))
        self.root.after(1000, self.tick)

    def on_close(self):
        for j in self.joins.values():
            j.leave()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use({"Darwin": "aqua", "Windows": "vista"}.get(SYSTEM, "clam"))
    except tk.TclError:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
