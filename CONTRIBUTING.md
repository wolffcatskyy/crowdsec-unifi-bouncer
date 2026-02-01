# Contributing to crowdsec-unifi-bouncer

Welcome! We're thrilled you're interested in contributing. This guide is designed for **everyone** — whether you're contributing your first line of code, using AI tools to help, or simply reporting ideas. No prior open source experience required.

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [First-Time Contributors](#first-time-contributors)
- [Using AI to Contribute](#using-ai-to-contribute)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Code of Conduct](#code-of-conduct)
- [Getting Help](#getting-help)

---

## Ways to Contribute

Contributions aren't limited to code. Here are ways you can help:

### Bug Reports & Issues
- Found something broken? [Open an issue](../../issues)
- UniFi API compatibility problems? Let us know
- Firewall rules not applying correctly? We want to fix it

### Documentation
- Improved installation instructions
- Clearer explanations of UniFi controller setup
- Troubleshooting guides based on your experience
- Examples for different network configurations (UDM, USG, Cloud Key)

### Features & Enhancements
- Support for additional UniFi platforms
- Better error messages and diagnostics
- Performance improvements
- IPv6 support enhancements

### Testing & Quality
- Test on your UniFi setup (UDM SE, UDM Pro, USG, etc.)
- Report edge cases or compatibility issues
- Help improve automated tests

### Community
- Answer questions from other users
- Share your deployment stories
- Help improve this documentation

---

## First-Time Contributors

Never contributed to open source before? Perfect. This project is a great place to start.

### Step 1: Fork the Repository

Click the **Fork** button at the top of the [repository page](../../). You now have your own copy to experiment with safely.

### Step 2: Clone Your Fork

```bash
git clone https://github.com/YOUR-USERNAME/crowdsec-unifi-bouncer.git
cd crowdsec-unifi-bouncer
```

### Step 3: Create a Branch

```bash
git checkout -b fix/my-fix-name
# or for features:
git checkout -b feature/my-feature-name
```

**Branch naming conventions:**
- `fix/` — bug fixes (`fix/csrf-token-parsing`)
- `feature/` — new features (`feature/ipv6-support`)
- `docs/` — documentation (`docs/udm-setup-guide`)
- `test/` — testing improvements (`test/health-endpoint`)

### Step 4: Make Your Changes

See [Making Changes](#making-changes) below.

### Step 5: Commit and Push

```bash
git add .
git commit -m "Fix: CSRF token extraction for newer firmware"
git push origin fix/my-fix-name
```

**Commit message format:**
- `Fix:` for bug fixes
- `Feature:` for new features
- `Docs:` for documentation
- `Test:` for test additions

### Step 6: Open a Pull Request

1. Go to the original repository
2. Click **Pull Requests** → **New Pull Request**
3. Select your branch
4. Fill out the PR template
5. Submit!

---

## Using AI to Contribute

We **welcome and encourage** AI-assisted contributions. AI tools (Claude, ChatGPT, GitHub Copilot, etc.) can help you generate code, write tests, improve documentation, and debug issues.

### Architecture Context for AI

Paste this into your AI assistant along with the issue you want to work on:

```
I want to contribute to crowdsec-unifi-bouncer. Here's the project context:

- Single Python file: bouncer.py (~900 lines)
- Only dependency: requests
- Docker: python:3.11-alpine, non-root user, health check on port 8080
- Config: all environment variables (loaded at module level with os.getenv)
- Classes: HealthStatus (thread-safe), HealthCheckHandler (/health, /ready, /live), CrowdSecClient (LAPI stream API), UniFiClient (controller API with cookie auth + CSRF), UniFiBouncer (orchestration)
- CrowdSec stream API for efficient delta updates (new/deleted decisions)
- UniFi firewall address groups with chunking (max 10k IPs per group)
- Auto WAN_IN + WAN_LOCAL drop rules per group
- Exponential backoff on UniFi API errors (502/503/504/429)
- Auto re-auth on 401 (expired session)
- MAX_IPS cap with freshness prioritization (local > community, sorted by remaining duration)
- Periodic full refresh every 10 cycles to rotate stale IPs
- Memory-conscious: gc.collect(), batch processing, memory logging

The issue I want to work on is: [paste issue title and body here]
```

Then paste the contents of `bouncer.py` and ask your AI to implement the fix/feature.

### Guidelines for AI-Assisted Work

**You are always responsible for your contribution.**

#### Required

1. **Review everything before submitting** — read every line, understand what it does
2. **Disclose AI assistance in your PR:**
   ```
   **AI Assistance:** Generated using [tool] with prompts focusing on [specific area]
   **Validation:** Tested in [your setup], verified [specific test cases]
   **Changes Made:** Manually reviewed and adjusted [list specific changes]
   ```
3. **Test thoroughly** — run the code locally, test error conditions
4. **Validate against project standards** — follows our code style, works with Docker setup

#### What We Won't Accept

- Unreviewed or untested AI output ("AI slop")
- Code you don't understand
- Changes that don't address a specific issue
- Low-quality generic "improvements"

### AI-Friendly Issue Template

When opening an issue, provide context that both AI tools and humans can work with:

```markdown
## Issue Title
[Clear, specific description]

## Current Behavior
[What happens now]

## Expected Behavior
[What should happen]

## Environment
- UniFi device: [e.g., UDM SE, UDM Pro, USG]
- UniFi firmware: [e.g., 4.0.6]
- CrowdSec version: [e.g., 1.6.x]
- Docker version: [e.g., 24.0.2]
- OS: [e.g., Ubuntu 22.04, Synology DSM 7.3]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [Result]

## Logs
[Relevant error messages or logs]

## Suggested Solution (optional)
[Your idea for fixing this]
```

---

## Development Setup

### Prerequisites

```bash
# Python 3.11+
python3 --version

# Install dependencies
pip install -r requirements.txt

# You'll need:
# - A CrowdSec instance with a bouncer API key
# - A UniFi controller with admin credentials
```

### Local Testing

```bash
# Configure credentials
export CROWDSEC_BOUNCER_API_KEY="your-key"
export CROWDSEC_URL="http://localhost:8080"
export UNIFI_HOST="https://192.168.1.1"
export UNIFI_USER="admin"
export UNIFI_PASS="your-password"
export UNIFI_SKIP_TLS_VERIFY="true"
export LOG_LEVEL="DEBUG"

# Run
python bouncer.py
```

### Docker Testing

```bash
docker build -t crowdsec-unifi-bouncer:dev .
docker run --env-file .env crowdsec-unifi-bouncer:dev
```

---

## Making Changes

### Code Style

```python
# Use f-strings for formatting
log.info(f"Synced {count} IPs to {group_name}")

# Use the module-level log object (not print)
log.debug(f"Request: {method} {url}")
log.warning(f"Retry {attempt}/{max_retries} after {delay}s")
log.error(f"Failed to update group: {e}")

# Environment variables at module level with defaults
UPDATE_INTERVAL = int(os.getenv("UPDATE_INTERVAL", "60"))
MAX_IPS = int(os.getenv("MAX_IPS", "0"))
```

### Key Constraints

- **Single file** — `bouncer.py` should remain self-contained
- **Single dependency** — `requests` only, no new deps without discussion
- **Thread safety** — `HealthStatus` uses `threading.Lock()`; be aware of concurrent access
- **Memory management** — use `del` + `gc.collect()` for large data structures
- **Both rule types** — changes to firewall rules must handle WAN_IN and WAN_LOCAL
- **Graceful failure** — errors in the sync loop should be logged and retried, not crash

### Pre-Submission Checklist

- [ ] Changes work locally
- [ ] Tested with `LOG_LEVEL=DEBUG`
- [ ] Health endpoint (`/health`) still returns correct status
- [ ] Error messages are clear
- [ ] No debug code left in commits
- [ ] Documentation updated if needed

---

## Submitting Pull Requests

### PR Template

```markdown
## Description
Brief summary of what this PR does.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Problem It Solves
Which issue does this address? (Link: #123)

## How Was This Tested?
- UniFi device: [model and firmware]
- CrowdSec version: [version]
- Scenarios verified: [list]

## Checklist
- [ ] I've tested this locally
- [ ] Health endpoints still work
- [ ] I've updated documentation if needed
- [ ] My code follows the project style
- [ ] No debug code or secrets in commits

## AI Assistance (if applicable)
**Tools Used:** Claude / ChatGPT / GitHub Copilot
**Scope:** Generated [specific part], reviewed and validated [changes made]
**Validation:** Tested in [environment], verified [specific test cases]
```

### Review Process

1. We'll review within a few days
2. We might request changes — this is normal and collaborative
3. Once approved, we'll merge and you'll be credited as a contributor

---

## Code of Conduct

- **Be respectful** to all contributors
- **Welcome diverse perspectives** and experiences
- **Ask questions** rather than make assumptions
- **Assume good intent** in interactions

---

## Getting Help

**"I'm not a programmer, can I still contribute?"**
Absolutely! Documentation, testing, and reporting issues are huge helps.

**"Can I use AI tools?"**
Yes! See [Using AI to Contribute](#using-ai-to-contribute). Just review and test everything.

**"How long until my PR is reviewed?"**
We aim for a few days. If it's been a week, ping us politely.

**"What if my PR is rejected?"**
That's okay! We'll explain why and suggest improvements. You can revise and resubmit.

**"I don't have a UniFi device, can I still contribute?"**
Yes! Documentation improvements, code review, and issue triage don't require hardware. For code changes, describe your test approach in the PR and we'll validate on real hardware.

---

## Open Issues — Great Starting Points

There are **10 open enhancement issues**, organized by version milestones:

- **v1.1** — Near-term improvements
- **v1.2** — Medium-term features
- **v1.3** — Longer-term goals

Browse them at: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues

---

## Recognition

Contributors are listed on the GitHub contributors page and mentioned in release notes for significant contributions.

---

**Ready to contribute? Pick an issue from the [issues page](../../issues) and get started!**
