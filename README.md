# IGMP Test Tool

Cross-platform tool (macOS, Windows, Linux) for subscribing to multicast
streams — ASM and SSM — with live receive statistics and IGMP querier
analysis. Python standard library only, no dependencies. Two variants with
identical functionality:

| Variant | File | GUI |
|---|---|---|
| Native app | `igmp_join_gui.py` | Tkinter (available as prebuilt executable) |
| Web GUI | `igmp_join_tool.py` | Browser at `http://127.0.0.1:8688` |

## Download

Prebuilt binaries under [**Releases**](https://github.com/Gemini2350/igmp-test-tool/releases)
(built automatically by GitHub Actions):

- **macOS** (Intel + Apple Silicon, universal): `IGMP-Test-Tool-macOS-universal.zip` —
  unzip and run. Not notarized: on first launch right-click → Open, or
  `xattr -cr "IGMP Test Tool.app"`.
- **Windows**: `IGMP-Test-Tool-Windows.exe` — runs directly, no Python required
  (confirm the SmartScreen warning once). Local build still possible via
  `build_windows.bat`.
- Without build: `python3 igmp_join_gui.py`.

## Web GUI variant

```bash
python3 igmp_join_tool.py
```

Windows: `py igmp_join_tool.py` — or double-click `Start IGMP Test Tool.bat`
(Mac: `Start IGMP Test Tool.command`; may need `chmod +x` or right-click →
Open once because of Gatekeeper).

The browser opens automatically at `http://127.0.0.1:8688`.
Options: `--port <n>` (GUI port), `--no-browser`.

## Usage

| Field | Meaning |
|---|---|
| Multicast group | Required, e.g. `239.1.1.1` |
| Source | Optional — with a source an SSM join (IGMPv3, INCLUDE mode) is sent, without one an ASM join |
| Interface | Interface the IGMP report is sent on. The list refreshes automatically (e.g. when a USB adapter is plugged in); ⟳ forces an immediate refresh |
| UDP port | Optional — with a port the tool counts received packets and shows the bitrate (e.g. `5004` for ST 2110/AES67); without a port only the membership is held |

The green dot pulses while packets are arriving. If the interface goes down
under an active join, the row turns red ("interrupted") and the tool
re-joins automatically once the interface is back. Joins stay active until
ended via **Leave** / **Leave all** or the tool is closed (IGMP Leave is sent
cleanly).

## Querier analysis

Both variants can analyse the IGMP querier on the network ("Start analysis"
button): querier IP, IGMP version (v1/v2/v3), query interval (from the QQIC
field for v3, additionally measured between two general queries), max
response time, the querier's MAC address including vendor (OUI lookup online
via macvendors.com) and — if several queriers are visible — which one wins
the election (lowest IP).

This requires a raw socket (**root/administrator**):

- **Windows**: right-click the exe → *Run as administrator*
- **macOS**: `sudo "…/IGMP Test Tool.app/Contents/MacOS/IGMP Test Tool"`
  or `sudo python3 igmp_join_gui.py` / `sudo python3 igmp_join_tool.py`

General queries typically arrive only every 60–125 s — wait a moment after
starting the analysis. Joins/statistics keep working without elevated
privileges.

## Notes

- Whether IGMPv2 or v3 is sent is decided by the OS stack (or the querier on
  the network). SSM joins require IGMPv3 on the path to the router.
- Verify memberships: macOS `netstat -gn`, Linux `ip maddr` /
  `cat /proc/net/igmp`, Windows `netsh interface ipv4 show joins`.
- A firewall exception for Python may be needed when using receive
  statistics (port).
- Unhandled errors are written to `igmp-test-tool-crash.log` in the temp
  directory (Windows: `%TEMP%`, macOS/Linux: `$TMPDIR` / `/tmp`).
