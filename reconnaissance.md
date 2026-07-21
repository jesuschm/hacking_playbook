# Reconnaissance

Reconnaissance techniques and tools for penetration testing.

## DNS and subdomain reconnaissance

### A Records

A records map a domain name to an IPv4 address. They are the most fundamental DNS records, directly resolving hostnames to IP addresses.

**Query A records:**

```bash
nslookup -type=A www.target.com
```

The IP address shown is the A record value for the hostname.

### CNAME Records

CNAME (Canonical Name) records create an alias from one domain name to another. They point a subdomain to another hostname rather than directly to an IP address.

**Query CNAME records:**

```bash
nslookup --type=CNAME subdomain.target.com
```

### TXT Records

TXT records store arbitrary text data associated with a domain or subdomain.

**Query TXT records:**

```bash
nslookup -type=TXT target.com
```


In penetration testing, TXT records can reveal:
- Hidden subdomains
- External services in use
- Configuration information
- Exposed tokens or credentials (if misconfigured)

### MX Records

MX (Mail Exchange) records specify mail servers responsible for accepting email messages for a domain. Each MX record includes:

- **Hostname**: The mail server hostname
- **Priority value**: A numerical value (0-65535) indicating preference order. Lower numbers have higher priority.

**Query MX records:**

```bash
nslookup -type=MX target.com
```

Mail servers are contacted in order from lowest to highest priority number.

## Useful Resources

- [VirusTotal](https://www.virustotal.com/) - Analyze files, URLs, IPs, and domains for malware and threat intelligence.
- [ANY.RUN](https://app.any.run/) - Interactive malware sandbox for analyzing files, URLs, and emails in a live Windows/Linux environment.
- [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) - Standard, harmless test string used to verify antivirus/EDR detection without handling real malware.

