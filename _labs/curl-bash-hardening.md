---
title: Hardening the infamous `curl | bash`
subtitle: Safer one-liners developers will actually use
excerpt: Gradually improve the pattern with pinning, checksums, and safer shells.
tags: [shell, supply-chain, installer]
---
**Scenario:** Replace risky one-liners with a safer, minimally-changed variant.

**Try it locally:**
```bash
# Example: verify checksum before execution
url="https://example.com/install.sh"
curl -fsSLO "$url" 
curl -fsSLO "$url.sha256"
sha256sum -c install.sh.sha256
bash install.sh
```

**What you’ll learn:** integrity checks, explicit tools, and reversible steps.
