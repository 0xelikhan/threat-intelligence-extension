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
    const gti = vt?.gti;
    if (gti?.verdict) {
      const v = String(gti.verdict).toUpperCase();
      const sev = gti.severity ? ` / ${gti.severity}` : '';
      if (v === 'MALICIOUS') return `MALICIOUS (GTI${sev})`;
      if (v === 'SUSPICIOUS') return `SUSPICIOUS (GTI${sev})`;
      if (v === 'BENIGN' || v === 'HARMLESS') return 'CLEAN (GTI)';
    }
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
        const v = r.virustotal;
        if (v.notFound) {
          lines.push(`**VirusTotal:** not indexed  `);
        } else {
          lines.push(`**VirusTotal:** ${v.malicious || 0}/${v.total || 0} malicious · reputation ${v.reputation ?? 0}  `);
          if (v.link) lines.push(`**VT link:** ${v.link}  `);
          if (v.gti?.verdict) lines.push(`**GTI:** ${v.gti.verdict}${v.gti.severity ? ' / ' + v.gti.severity : ''}${v.gti.threatScore != null ? ' · score ' + v.gti.threatScore : ''}  `);
          if (v.mandiantScore != null) lines.push(`**Mandiant IC:** ${v.mandiantScore}  `);
          if (v.threatFamily) lines.push(`**Threat:** ${v.threatFamily}  `);
          if (v.threatCategories?.length) lines.push(`**Categories:** ${v.threatCategories.join(', ')}  `);
          if (v.popularity?.length) lines.push(`**Popularity:** ${v.popularity.slice(0, 3).map(p => p.source + ': ' + p.rank).join(' · ')}  `);
          if (v.tags?.length) lines.push(`**Tags:** ${v.tags.slice(0, 10).join(', ')}  `);
          if (v.sigmaHits?.length) lines.push(`**Sigma:** ${v.sigmaHits.slice(0, 5).map(s => (s.title || s.id) + (s.level ? ' [' + s.level + ']' : '')).join(' · ')}  `);
          if (v.idsHits?.length) lines.push(`**IDS:** ${v.idsHits.slice(0, 5).map(s => s.alert || s.category).join(' · ')}  `);
          if (v.yaraHits?.length) lines.push(`**YARA:** ${v.yaraHits.slice(0, 5).map(s => s.name || s.ruleset).join(' · ')}  `);
          if (v.sandbox?.length) lines.push(`**Sandbox:** ${v.sandbox.slice(0, 3).map(s => s.sandbox + ': ' + s.category).join(' · ')}  `);
          if (v.signature) lines.push(`**Signature:** ${v.signature.verified || 'unsigned'}${v.signature.signers ? ' · ' + String(v.signature.signers).split(';')[0] : ''}  `);
          if (v.jarm) lines.push(`**JARM:** \`${v.jarm}\`  `);
          if (v.httpsCert) {
            const c = v.httpsCert;
            const iss = c.issuer?.CN || c.issuer?.O || '';
            const sub = c.subject?.CN || '';
            if (iss || sub) lines.push(`**TLS Cert:** ${sub}${sub && iss ? ' / ' : ''}${iss}  `);
          }
          if (v.fileExtras?.imphash) lines.push(`**imphash:** \`${v.fileExtras.imphash}\`  `);
          if (v.fileExtras?.ssdeep) lines.push(`**ssdeep:** \`${v.fileExtras.ssdeep}\`  `);
        }
      }
      if (r.vtBehavior && !r.vtBehavior.error && !r.vtBehavior.notFound) {
        const b = r.vtBehavior;
        if (b.processesCreated?.length) lines.push(`**Processes:** ${b.processesCreated.slice(0, 5).map(p => '`' + p + '`').join(', ')}  `);
        if (b.commandExecutions?.length) lines.push(`**Commands:** ${b.commandExecutions.slice(0, 3).map(c => '`' + c.slice(0, 200) + '`').join(' | ')}  `);
        if (b.filesDropped?.length) lines.push(`**Files dropped:** ${b.filesDropped.slice(0, 5).map(f => '`' + f.path + '`').filter(Boolean).join(', ')}  `);
        if (b.registryKeysSet?.length) lines.push(`**Registry set:** ${b.registryKeysSet.slice(0, 5).map(k => '`' + k + '`').join(', ')}  `);
        if (b.mutexesCreated?.length) lines.push(`**Mutexes:** ${b.mutexesCreated.slice(0, 5).map(m => '`' + m + '`').join(', ')}  `);
        if (b.dnsLookups?.length) lines.push(`**DNS queries:** ${b.dnsLookups.slice(0, 10).map(d => '`' + d + '`').join(', ')}  `);
        if (b.ipTraffic?.length) lines.push(`**IP traffic:** ${b.ipTraffic.slice(0, 10).map(ip => '`' + ip + '`').join(', ')}  `);
        if (b.mitre?.length) lines.push(`**MITRE:** ${b.mitre.slice(0, 8).map(m => m.id || '').filter(Boolean).join(', ')}  `);
      }
      if (r.gtiCollections && !r.gtiCollections.error && !r.gtiCollections.notFound && r.gtiCollections.count > 0) {
        const g = r.gtiCollections;
        if (g.grouped.threat_actor.length) lines.push(`**Threat Actor:** ${g.grouped.threat_actor.slice(0, 3).map(a => `[${a.name}](${a.link})`).join(', ')}  `);
        if (g.grouped.malware_family.length) lines.push(`**Malware:** ${g.grouped.malware_family.slice(0, 3).map(a => `[${a.name}](${a.link})`).join(', ')}  `);
        if (g.grouped.campaign.length) lines.push(`**Campaign:** ${g.grouped.campaign.slice(0, 3).map(a => `[${a.name}](${a.link})`).join(', ')}  `);
        if (g.grouped.report.length) lines.push(`**Reports:** ${g.grouped.report.slice(0, 3).map(a => `[${a.name}](${a.link})`).join(', ')}  `);
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
