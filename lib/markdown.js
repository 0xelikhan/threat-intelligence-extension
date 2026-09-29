/*
 * Threat Intelligence — Markdown report builder + Copilot prompt builder
 */
(function (root) {
  'use strict';

  function fmtDate(v) {
    if (!v) return '';
    if (typeof v === 'number') return new Date(v * (v < 1e12 ? 1000 : 1)).toISOString().slice(0, 10);
    try { return new Date(v).toISOString().slice(0, 10); } catch { return String(v); }
  }

  function iocIcon(type) {
    return ({
      ipv4: '🌐', ipv6: '🌐', domain: '🔗', url: '🔗',
      md5: '#', sha1: '#', sha256: '#',
      email: '✉', cve: '⚠', mitre_technique: '⚔', mitre_tactic: '⚔',
      registry: '⚙', filepath: '📁',
    })[type] || '•';
  }

  function verdictBadge(enriched) {
    const vt = enriched?.results?.virustotal;
    const ab = enriched?.results?.abuseipdb;
    if (vt && !vt.notFound && !vt.error && (vt.malicious || 0) > 0) {
      return `MALICIOUS (${vt.malicious}/${vt.total} on VT)`;
    }
    if (ab && !ab.error && (ab.confidence || 0) >= 75) {
      return `MALICIOUS (AbuseIPDB confidence ${ab.confidence})`;
    }
    if (vt && (vt.suspicious || 0) > 0) return `SUSPICIOUS (${vt.suspicious} VT engines)`;
    if (ab && (ab.confidence || 0) >= 25) return `SUSPICIOUS (AbuseIPDB ${ab.confidence})`;
    if (vt && !vt.notFound && !vt.error) return 'CLEAN';
    return 'UNKNOWN';
  }

  function buildMarkdown(enrichments, opts = {}) {
    const lines = [];
    lines.push(`# Threat Intelligence Report`);
    lines.push(`_Generated ${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC_`);
    if (opts.pageUrl) lines.push(`_Source: ${opts.pageUrl}_`);
    lines.push('');

    // Summary table
    lines.push(`## Summary`);
    lines.push('');
    lines.push('| Indicator | Type | Verdict |');
    lines.push('|---|---|---|');
    for (const e of enrichments) {
      const v = opts.defang ? SOCParser.defang(e.ioc.value) : e.ioc.value;
      lines.push(`| \`${v}\` | ${e.ioc.type} | ${verdictBadge(e)} |`);
    }
    lines.push('');

    // Detailed sections
    lines.push(`## Details`);
    for (const e of enrichments) {
      const v = opts.defang ? SOCParser.defang(e.ioc.value) : e.ioc.value;
      lines.push('');
      lines.push(`### \`${v}\` (${e.ioc.type})`);
      lines.push(`**Verdict:** ${verdictBadge(e)}  `);

      const r = e.results || {};
      if (r.ipApi && !r.ipApi.error) {
        lines.push(`**Geolocation:** ${r.ipApi.city || ''}, ${r.ipApi.region || ''}, ${r.ipApi.country || ''} (${r.ipApi.countryCode || ''})  `);
        lines.push(`**ASN:** ${r.ipApi.asn || ''} ${r.ipApi.org || r.ipApi.isp || ''}  `);
        if (r.ipApi.reverseDns) lines.push(`**rDNS:** \`${r.ipApi.reverseDns}\`  `);
        const flags = [];
        if (r.ipApi.isProxy) flags.push('proxy');
        if (r.ipApi.isHosting) flags.push('hosting');
        if (r.ipApi.isMobile) flags.push('mobile');
        if (flags.length) lines.push(`**Flags:** ${flags.join(', ')}  `);
      }
      if (r.reverseDns && !r.reverseDns.error && r.reverseDns.ptr?.length) {
        lines.push(`**PTR:** ${r.reverseDns.ptr.map(p => `\`${p}\``).join(', ')}  `);
      }
      if (r.forwardDns && !r.forwardDns.error) {
        const a = (r.forwardDns.a || []).map(x => x.data).join(', ');
        const mx = (r.forwardDns.mx || []).map(x => x.data).join(', ');
        const ns = (r.forwardDns.ns || []).map(x => x.data).join(', ');
        if (a) lines.push(`**A records:** ${a}  `);
        if (mx) lines.push(`**MX:** ${mx}  `);
        if (ns) lines.push(`**NS:** ${ns}  `);
      }
      if (r.rdap && !r.rdap.error) {
        if (r.rdap.registrar) lines.push(`**Registrar:** ${r.rdap.registrar}  `);
        if (r.rdap.created) lines.push(`**Registered:** ${fmtDate(r.rdap.created)}  `);
        if (r.rdap.expires) lines.push(`**Expires:** ${fmtDate(r.rdap.expires)}  `);
        if (r.rdap.name) lines.push(`**Network:** ${r.rdap.name}  `);
        if (r.rdap.country && !r.ipApi) lines.push(`**Country:** ${r.rdap.country}  `);
        if (r.rdap.abuseContacts?.length) lines.push(`**Abuse contact:** ${r.rdap.abuseContacts.join(', ')}  `);
      }
      if (r.virustotal && !r.virustotal.error) {
        if (r.virustotal.notFound) {
          lines.push(`**VirusTotal:** not indexed  `);
        } else {
          lines.push(`**VirusTotal:** ${r.virustotal.malicious || 0}/${r.virustotal.total || 0} malicious · reputation ${r.virustotal.reputation ?? 0}  `);
          if (r.virustotal.link) lines.push(`**VT link:** ${r.virustotal.link}  `);
        }
      }
      if (r.abuseipdb && !r.abuseipdb.error) {
        lines.push(`**AbuseIPDB:** confidence ${r.abuseipdb.confidence}/100 · ${r.abuseipdb.totalReports} reports · usage: ${r.abuseipdb.usageType || ''}  `);
        if (r.abuseipdb.isTor) lines.push(`**Tor exit node:** yes  `);
      }
      if (r.greynoise && !r.greynoise.error && !r.greynoise.notFound) {
        lines.push(`**GreyNoise:** ${r.greynoise.classification || ''}${r.greynoise.name ? ' ' + r.greynoise.name : ''}  `);
      }
      if (r.nvd && !r.nvd.error) {
        lines.push(`**CVSS:** ${r.nvd.cvssScore ?? ''} (${r.nvd.severity || ''})  `);
        if (r.nvd.description) lines.push(`> ${r.nvd.description.slice(0, 400)}${r.nvd.description.length > 400 ? '…' : ''}`);
      }
    }
    return lines.join('\n');
  }

  function buildCopilotPrompt(enrichments, opts = {}) {
    const lines = [];
    lines.push(`SOC alert review. Using the enriched indicator data below, produce:`);
    lines.push('');
    lines.push(`1. Verdict (malicious / suspicious / benign / inconclusive) with confidence.`);
    lines.push(`2. Likely threat scenario: campaign, malware family, or TTPs matching this pattern.`);
    lines.push(`3. Recommended actions: containment steps, KQL hunt queries (Defender/Sentinel), enrichment gaps.`);
    lines.push(`4. Pivot points for the next hunt.`);
    lines.push('');
    lines.push(`Bullet points only. No filler.`);
    lines.push('');
    if (opts.pageUrl) lines.push(`Source: ${opts.pageUrl}`);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push(buildMarkdown(enrichments, opts));
    return lines.join('\n');
  }

  root.SOCReport = { buildMarkdown, buildCopilotPrompt, verdictBadge, iocIcon };
})(typeof self !== 'undefined' ? self : globalThis);
