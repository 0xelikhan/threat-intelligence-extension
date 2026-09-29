# Threat Intelligence

Edge extension for IOC extraction and enrichment.

## Install (unpacked)

1. Open `edge://extensions`
2. Enable Developer mode
3. Load unpacked, select this folder

## Enrichment sources

**No key required**
- ip-api.com (geolocation, ASN, rDNS, hosting/proxy flags)
- Google DNS-over-HTTPS (A / AAAA / MX / NS / TXT / PTR)
- RDAP (registrar, creation/expiry dates, abuse contacts, network info)
- NVD (CVE metadata, CVSS score)

**Key required (Options page)**
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AbuseIPDB (free 1k/day): https://www.abuseipdb.com/account/api
- GreyNoise (optional): https://viz.greynoise.io/account/api-key
- Custom sources: `{ioc}` placeholder in URL, arbitrary header name

## Detected IOCs

IPv4/v6 (defanged forms), domains, URLs, MD5/SHA1/SHA256, emails, CVEs, MITRE ATT&CK IDs, registry keys, filepaths.

## Interfaces

- Side panel: full workflow, page scan, batch enrichment, case notes, report export
- Popup: single-IOC lookup
- Hover tooltip: any highlighted IOC on any page
- Context menu: right-click selection to enrich or send to Copilot

## Copilot

`Copilot` button copies a formatted prompt to clipboard and opens copilot.microsoft.com pre-filled. Works with any Copilot account, no API key.

## Report export

`Report` button copies a Markdown report of all enriched IOCs to clipboard for pasting into tickets or case notes.
