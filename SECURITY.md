# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public issue**
2. Email the maintainer or use GitHub's private vulnerability reporting
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

## Security Considerations

This bouncer handles:
- **CrowdSec API keys** - Keep your `.env` file secure
- **UniFi credentials** - Use a dedicated admin account with minimal permissions
- **Firewall rules** - The bouncer modifies your firewall; test in staging first

### Best Practices

1. **Use dedicated credentials**: Create a UniFi admin account just for the bouncer
2. **Network isolation**: Run on a trusted network segment
3. **TLS verification**: Only disable `UNIFI_SKIP_TLS_VERIFY` if you understand the risks
4. **Monitor logs**: Watch for unexpected behavior
5. **Keep updated**: Use the latest version for security fixes
