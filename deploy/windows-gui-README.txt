egress GUI for Windows
======================

Requirements
- Windows 10 or Windows 11 with the Microsoft Edge WebView2 runtime.
  Windows 11 includes it. On older Windows 10, install the Evergreen runtime
  from Microsoft if the app does not start.
- The egress daemon 0.5.1 or newer installed on the same machine and connected.

Run
- Start egress-gui.exe. The app reads the local daemon token from
  %ProgramData%\egress-gui\api-token. No administrator prompt is needed.
- The tray icon keeps the app available after the window is closed.

Notes
- This build is unsigned, so Windows SmartScreen may warn on first run.
- The app only talks to the egress daemon on 127.0.0.1.
