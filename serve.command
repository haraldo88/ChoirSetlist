#!/bin/bash
# Double-click this file to start a tiny local web server for the
# Choir Setlist app. Without it, browsers block fetch() of the .mp3
# samples because the file:// origin is treated as insecure.
#
# First-time setup: open Terminal once and run
#   chmod +x "$(pwd)/serve.command"
# in this folder so Finder is allowed to execute it.

cd "$(dirname "$0")"

PORT=8000

echo ""
echo "  ┌─────────────────────────────────────────────┐"
echo "  │  Choir Setlist — local server                │"
echo "  │                                              │"
echo "  │  Open in browser:                            │"
echo "  │      http://localhost:$PORT                     │"
echo "  │                                              │"
echo "  │  Press Ctrl+C in this window to stop.        │"
echo "  └─────────────────────────────────────────────┘"
echo ""

# Open the browser tab automatically after the server has had a moment
# to start up. & runs it in the background.
(sleep 1 && open "http://localhost:$PORT") &

# python3 ships with macOS. -m http.server is a stdlib one-liner.
python3 -m http.server "$PORT"
