# macOS code signing & notarization (Developer ID / direct distribution)

The build workflow signs and notarizes the macOS app automatically **once the
six repository secrets below exist**. Without them it falls back to the
previous ad-hoc build, so nothing breaks for forks.

This is the *Developer ID* path (direct download, not the Mac App Store): the
full feature set stays (raw sockets, elevated helper), and the notarized app
opens with a normal double-click — no more "right-click → Open".

## One-time: create the certificate and password

You need an active Apple Developer Program membership.

1. **Developer ID Application certificate**
   - Xcode → Settings → Accounts → your team → *Manage Certificates* → **+** →
     *Developer ID Application*. (Or create it on
     https://developer.apple.com/account/resources/certificates .)
   - In *Keychain Access*, find "Developer ID Application: NAME (TEAMID)",
     right-click → **Export** → save as `cert.p12`, set an export password.
   - Convert to base64 for the secret:
     ```bash
     base64 -i cert.p12 | pbcopy      # now in your clipboard
     ```

2. **App-specific password for notarization**
   - https://account.apple.com → Sign-In and Security → **App-Specific
     Passwords** → generate one (e.g. name it "notarytool").

3. **Team ID**: the 10-character code shown at
   https://developer.apple.com/account (Membership details), also the
   `(TEAMID)` in the certificate name.

## Add the repository secrets

GitHub repo → *Settings* → *Secrets and variables* → *Actions* → *New
repository secret*, six times:

| Secret name | Value |
|---|---|
| `MACOS_CERTIFICATE_P12` | the base64 string from step 1 |
| `MACOS_CERTIFICATE_PASSWORD` | the .p12 export password |
| `MACOS_SIGN_IDENTITY` | `Developer ID Application: NAME (TEAMID)` (exactly as in Keychain) |
| `MACOS_NOTARY_APPLE_ID` | your Apple ID e-mail |
| `MACOS_TEAM_ID` | the 10-char Team ID |
| `MACOS_NOTARY_PASSWORD` | the app-specific password from step 2 |

## Build a signed release

Push a version tag as usual:

```bash
git tag v1.7.0 && git push origin v1.7.0
```

The `macos` job now signs (hardened runtime + `entitlements.plist`),
submits to Apple's notary service, waits for the result, staples the ticket,
and attaches the signed `IGMP-Test-Tool-macOS-universal.zip` to the release.

Verify a downloaded build locally:

```bash
spctl -a -vv "IGMP Test Tool.app"      # -> accepted, source=Notarized Developer ID
codesign --verify --deep --strict --verbose=2 "IGMP Test Tool.app"
```

## Notes

- Notarization does **not** restrict what the app may do at runtime: the
  querier analysis and "Detect port" (elevated helper via the system password
  dialog) keep working. Only the App Store sandbox would forbid those, which
  is why this is Developer ID, not App Store.
- The Windows `.exe` is still unsigned. Removing its SmartScreen warning needs
  a separate Authenticode certificate (OV/EV from a CA such as Sectigo or
  DigiCert); that can be wired into the `windows` job the same way if wanted.
