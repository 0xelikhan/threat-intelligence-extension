# Threat Intelligence

Edge extension for IOC extraction and enrichment.

## Install (unpacked)

1. Open `edge://extensions`
2. Enable Developer mode
3. Load unpacked, select this folder

## Enrichment sources

### No key required (bundled, always available)

- **ip-api.com** — geolocation, ASN, rDNS, hosting/proxy flags
- **Google DNS-over-HTTPS** — A / AAAA / MX / NS / TXT / PTR (forward + reverse)
- **RDAP** — domain registrar, creation/expiry, abuse contacts; IP range, allocation, abuse
- **NVD** — CVE metadata, CVSS score
- **ProxyCheck** — VPN / proxy / Tor detection (keyless free tier)
- **CIRCL hashlookup** — NSRL-based known-good + known-malicious hash classification
- **RIPE Stat** — prefix / ASNs / abuse contacts / geoloc for IPs and domains
- **Team Cymru** — IP → ASN, prefix, country, registry, allocation date (via DoH)
- **SANS ISC / DShield** — aggregated threatfeed hits, attack counts, ASN abuse contact
- **DNSSEC validation** — secure / unsigned / bogus state for domains and URL hostnames

### Key required (Options page)

| Source | Covers | Free tier | Get key |
|---|---|---|---|
| VirusTotal | IP / domain / URL / hash | 500 req/day | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | IP | 1k req/day | https://www.abuseipdb.com/account/api |
| GreyNoise Community | IP | ~1k req/day | https://viz.greynoise.io/account/api-key |
| **abuse.ch Auth-Key** | one key, three enrichers | generous | https://auth.abuse.ch/ |
| &nbsp;&nbsp;↳ URLhaus | URL / domain / IP / hash | | |
| &nbsp;&nbsp;↳ ThreatFox | IOC search | | |
| &nbsp;&nbsp;↳ MalwareBazaar | hash metadata, YARA, families | | |
| IPInfo | IP | 50k/mo | https://ipinfo.io/account/token |
| Shodan | IP (ports, CVEs, services) | 100/mo | https://account.shodan.io/ |
| AlienVault OTX | IP / domain / URL / hash | generous | https://otx.alienvault.com/api |
| urlscan.io | URL / domain / IP | 1k/day | https://urlscan.io/user/profile/ |
| CrowdSec | IP | 10k/day | https://app.crowdsec.net/settings/api-keys |
| Pulsedive | IP / domain / URL | free | https://pulsedive.com/account/ |
| Censys | IP (ports, services, software) | 250/mo | https://search.censys.io/account/api |
| Hybrid Analysis | hash | free | https://www.hybrid-analysis.com/apikeys/info |
| ANY.RUN | hash / URL | free | https://app.any.run/profile/ |
| FullHunt | domain / IP | free | https://fullhunt.io/user/settings/ |
| Polyswarm | hash / URL | free | https://polyswarm.network/account/api-keys |
| Intelligence X | IP / domain / URL / hash / email | limited | https://intelx.io/account?tab=developer |
| PhishTank | URL | free, limited | https://www.phishtank.com/api_register.php |

### Custom sources

Any REST endpoint with an `{ioc}` placeholder in the URL and an arbitrary header name for the key.

## Detected IOCs

IPv4/v6 (defanged forms), domains, URLs, MD5/SHA1/SHA256, emails, CVEs, MITRE ATT&CK IDs, registry keys, filepaths.

## Interfaces

- **Side panel** — full workflow, page scan, batch enrichment, case notes, report export
- **Popup** — single-IOC lookup
- **Hover tooltip** — any highlighted IOC on any page
- **Context menu** — right-click selection to enrich or send to Copilot

## Copilot

`Copilot` button copies a formatted prompt to clipboard and opens copilot.microsoft.com pre-filled. Works with any Copilot account, no API key.

## Report export

`Report` button copies a Markdown report of all enriched IOCs to clipboard for pasting into tickets or case notes.
