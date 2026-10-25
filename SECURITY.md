# NovaTunnel Security Policy

## Project Status

NovaTunnel is an experimental, educational VPN project.

It implements a custom VPN protocol and has not undergone
an independent security audit.

Do not use NovaTunnel to protect production systems,
sensitive personal information, or critical infrastructure.

## Implemented Security Controls

NovaTunnel includes:

- X25519 key exchange.
- ChaCha20-Poly1305 authenticated encryption.
- Server identity verification using a pinned public key.
- Registered-peer authentication.
- Encrypted DATA packet authentication.
- Replay protection for DATA and control packets.
- IPv4 source-address validation.
- Authenticated keepalive and disconnect messages.
- Protection against persisting active session keys.
- Dashboard login protection, CSRF validation, and rate limiting.
- Dashboard disabled by default and bound to localhost
  in the installer and example configuration.

## Security Testing

The following targeted checks have been completed:

- 12 standalone Python regression scripts passed.
- Python compilation passed.
- Live VPN connectivity verified.
- Unauthorized client rejection verified.
- Incorrect server identity rejection verified.
- Live DATA replay rejection verified.
- Manual client reconnection verified.
- Dashboard security configuration checks passed.

These results do not guarantee resistance to every attack.

## Known Limitations

1. The VPN uses a custom security protocol without
   independent cryptographic review.

2. The built-in dashboard does not configure HTTPS
   automatically. It must not be exposed directly over HTTP.

3. The built-in Flask development server is not suitable
   for production internet-facing deployment.

4. Intermittent "Invalid IPv4 packet" warnings were observed.
   Client-side IPv4 filtering was added, but the original
   cause has not been conclusively verified.

5. Secret scanning performed during development was
   preliminary and does not guarantee that all historical
   credentials or sensitive data have been detected.

6. Performance, denial-of-service resistance, reliability,
   and cross-platform compatibility require further testing.

## Recommended Usage

- Use only in controlled educational or isolated lab environments.
- Never commit real private keys or administrator credentials.
- Restrict access to administrative interfaces.
- Use securely generated credentials.
- Keep dependencies updated.
- Review source changes before deployment.

## Reporting Security Issues

Please report suspected vulnerabilities privately to the
repository maintainer.

Use GitHub private vulnerability reporting if the repository
has enabled it, or another private contact method provided
by the maintainer.

Do not disclose real credentials, private keys, or sensitive
information in public issue reports.

## Security Support

NovaTunnel is experimental. No production security support
or security certification is currently provided.
