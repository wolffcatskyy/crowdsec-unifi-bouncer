# Contributing to CrowdSec UniFi Bouncer

Thank you for your interest in contributing!

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Open a new issue with:
   - Clear title describing the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Version info (bouncer, CrowdSec, UniFi)

### Suggesting Features

Open an issue with the `enhancement` label describing:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives considered

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test with your UniFi setup
5. Commit with clear messages
6. Push and open a Pull Request

### Development Setup

```bash
# Clone
git clone https://github.com/wolffcatskyy/crowdsec-unifi-bouncer.git
cd crowdsec-unifi-bouncer

# Create .env with your credentials
cp .env.example .env
# Edit .env with your CrowdSec and UniFi details

# Run locally
python bouncer.py

# Or with Docker
docker compose up --build
```

### Code Style

- Use Python type hints where helpful
- Keep functions focused and documented
- Log important operations at INFO level
- Log debug details at DEBUG level

## Questions?

Open an issue or discussion - we're happy to help!
