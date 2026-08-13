# IGMP Test Tool

Plattformübergreifendes Tool (macOS, Windows, Linux) zum Abonnieren von
Multicast-Streams — ASM und SSM — mit Live-Empfangsstatistik.
Nur Python-Standardbibliothek, keine Abhängigkeiten. Zwei Varianten mit
identischem Funktionsumfang:

| Variante | Datei | GUI |
|---|---|---|
| Native App | `igmp_join_gui.py` | Tkinter (als ausführbare Datei baubar) |
| Web-GUI | `igmp_join_tool.py` | Browser auf `http://127.0.0.1:8688` |

## Download

Fertige macOS-App (Apple Silicon) unter
[**Releases**](https://github.com/Gemini2350/igmp-test-tool/releases) —
entpacken und starten.

## Native App / ausführbare Datei

- **macOS**: fertige App im [Release](https://github.com/Gemini2350/igmp-test-tool/releases)
  (ad-hoc signiert). Gatekeeper setzt beim Download das Quarantäne-Flag —
  einmalig Rechtsklick → Öffnen, oder `xattr -cr "IGMP Test Tool.app"`.
- **Windows**: `.exe` muss einmalig auf einem Windows-Rechner gebaut werden —
  Doppelklick auf `build_windows.bat` (braucht Python von python.org),
  Ergebnis liegt danach in `dist\IGMP Test Tool.exe` und läuft ohne Python.
- Direkt ohne Build: `python3 igmp_join_gui.py`.

## Web-GUI-Variante starten

```bash
python3 igmp_join_tool.py
```

Windows: `py igmp_join_tool.py` — oder einfach Doppelklick auf
`Start IGMP Test Tool.bat` (Mac: `Start IGMP Test Tool.command`, ggf. einmalig
`chmod +x` bzw. Rechtsklick → Öffnen wegen Gatekeeper).

Der Browser öffnet sich automatisch auf `http://127.0.0.1:8688`.
Optionen: `--port <n>` (GUI-Port), `--no-browser`.

## Bedienung

| Feld | Bedeutung |
|---|---|
| Multicast-Gruppe | Pflicht, z. B. `239.1.1.1` |
| Source | Optional — mit Source wird ein SSM-Join (IGMPv3, INCLUDE-Mode) gesendet, ohne ein ASM-Join |
| Interface | Interface, über das der IGMP-Report gesendet wird |
| UDP-Port | Optional — mit Port zählt das Tool empfangene Pakete und zeigt die Bitrate (z. B. `5004` für ST 2110/AES67); ohne Port wird nur die Membership gehalten |

Der grüne Punkt pulsiert, solange Pakete ankommen. Joins bleiben aktiv,
bis sie per **Leave** / **Alle verlassen** beendet werden oder das Tool
geschlossen wird (IGMP Leave wird sauber gesendet).

## Hinweise

- Ob IGMPv2 oder v3 gesendet wird, entscheidet der OS-Stack (bzw. der
  Querier im Netz). SSM-Joins benötigen IGMPv3 auf dem Weg zum Router.
- Verifizieren der Memberships: macOS `netstat -gn`, Linux `ip maddr` /
  `cat /proc/net/igmp`, Windows `netsh interface ipv4 show joins`.
- Firewall-Freigabe für Python kann nötig sein, wenn Empfangsstatistik
  (Port) genutzt wird.
