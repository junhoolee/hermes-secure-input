#!/bin/sh
# Criterion 8: one real round trip through Tailscale Serve with a real browser (Playwright chromium).
# Needs: Tailscale running with MagicDNS/HTTPS, `tailscale serve status` = "No serve config", ui/node_modules.
set -eu
cd "$(dirname "$0")/../ui"
SECURE_INPUT_LIVE_TAILSCALE=1 npx playwright test e2e/live-tailscale.spec.ts --project=chromium-desktop --reporter=list
/Applications/Tailscale.app/Contents/MacOS/Tailscale serve status
