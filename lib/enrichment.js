/*
 * Threat Intelligence: enrichment engine
 * All API calls happen from the background service worker (which has the host permissions)
 * or from extension pages. Content scripts should message the background instead.
 */
(function (root) {
  'use strict';

  const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
  const cache = new Map();

  function cacheKey(source, ioc) { return `${source}::${ioc}`; }

  function getCached(source, ioc) {
    const key = cacheKey(source, ioc);
    const hit = cache.get(key);
    if (!hit) return null;
    if (Date.now() - hit.at > CACHE_TTL_MS) { cache.delete(key); return null; }
    return hit.value;
  }

  function setCached(source, ioc, value) {
    cache.set(cacheKey(source, ioc), { at: Date.now(), value });
  }

  async function safeFetch(url, opts = {}, timeoutMs = 10000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, Object.assign({}, opts, { signal: ctrl.signal }));
      return res;
    } finally {
      clearTimeout(t);
    }
  }

  // ─── ip-api.com (free, no key) — geolocation + ASN + rDNS + org ─────────────
  async function ipApi(ip) {
    const cached = getCached('ip-api', ip);
    if (cached) return cached;
    const url = `https://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`;
    const res = await safeFetch(url);
    if (!res.ok) throw new Error(`ip-api HTTP ${res.status}`);
    const data = await res.json();
    if (data.status !== 'success') throw new Error(data.message || 'ip-api failure');
    const out = {
      source: 'ip-api.com',
      country: data.country,
      countryCode: data.countryCode,
      region: data.regionName,
      city: data.city,
      lat: data.lat,
      lon: data.lon,
      timezone: data.timezone,
      isp: data.isp,
      org: data.org,
      asn: data.as,
      asnName: data.asname,
      reverseDns: data.reverse,
      isProxy: data.proxy,
      isHosting: data.hosting,
      isMobile: data.mobile,
    };
    setCached('ip-api', ip, out);
    return out;
  }

  // ─── Google DNS-over-HTTPS (free, no key) ──────────────────────────────────
  async function dohResolve(name, type = 'A') {
    const cached = getCached('doh-' + type, name);
    if (cached) return cached;
    const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const res = await safeFetch(url);
    if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
    const data = await res.json();
    const answers = (data.Answer || []).map(a => ({ name: a.name, type: a.type, ttl: a.TTL, data: a.data }));
    setCached('doh-' + type, name, answers);
    return answers;
  }

  async function forwardDns(domain) {
    const [a, aaaa, mx, ns, txt] = await Promise.all([
      dohResolve(domain, 'A').catch(() => []),
      dohResolve(domain, 'AAAA').catch(() => []),
      dohResolve(domain, 'MX').catch(() => []),
      dohResolve(domain, 'NS').catch(() => []),
      dohResolve(domain, 'TXT').catch(() => []),
    ]);
    return { source: 'dns.google', a, aaaa, mx, ns, txt };
  }

  async function reverseDns(ip) {
    // Build in-addr.arpa or ip6.arpa
    let arpa;
    if (ip.includes(':')) {
      // IPv6 → nibble-reversed .ip6.arpa
      const expanded = expandIPv6(ip);
      arpa = expanded.split('').reverse().join('.') + '.ip6.arpa';
    } else {
      arpa = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    }
    const answers = await dohResolve(arpa, 'PTR');
    return { source: 'dns.google', ptr: answers.map(a => a.data) };
  }

  function expandIPv6(ip) {
    // Very simple expansion: pad each group to 4 hex chars, handle ::
    let parts;
    if (ip.includes('::')) {
      const [head, tail] = ip.split('::');
      const headParts = head ? head.split(':') : [];
      const tailParts = tail ? tail.split(':') : [];
      const missing = 8 - headParts.length - tailParts.length;
      parts = [...headParts, ...Array(missing).fill('0'), ...tailParts];
    } else {
      parts = ip.split(':');
    }
    return parts.map(p => p.padStart(4, '0')).join('').toLowerCase();
  }

  // ─── RDAP (free, no key, replaces WHOIS) ───────────────────────────────────
  async function rdapDomain(domain) {
    const cached = getCached('rdap-domain', domain);
    if (cached) return cached;
    // rdap.org bootstraps to the right registry
    const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
    const res = await safeFetch(url);
    if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
    const data = await res.json();

    const events = (data.events || []).reduce((acc, e) => {
      acc[e.eventAction] = e.eventDate;
      return acc;
    }, {});
    const registrar = (data.entities || [])
      .filter(e => (e.roles || []).includes('registrar'))
      .map(e => vcardName(e)).filter(Boolean)[0] || null;

    const out = {
      source: 'RDAP',
      handle: data.handle,
      ldhName: data.ldhName,
      status: data.status,
      created: events.registration,
      updated: events['last changed'],
      expires: events.expiration,
      registrar,
      nameservers: (data.nameservers || []).map(n => n.ldhName),
    };
    setCached('rdap-domain', domain, out);
    return out;
  }

  async function rdapIp(ip) {
    const cached = getCached('rdap-ip', ip);
    if (cached) return cached;
    const url = `https://rdap.org/ip/${encodeURIComponent(ip)}`;
    const res = await safeFetch(url);
    if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
    const data = await res.json();
    const events = (data.events || []).reduce((acc, e) => { acc[e.eventAction] = e.eventDate; return acc; }, {});
    const abuse = (data.entities || []).flatMap(collectAbuseContacts);
    const out = {
      source: 'RDAP',
      handle: data.handle,
      name: data.name,
      country: data.country,
      startAddress: data.startAddress,
      endAddress: data.endAddress,
      cidr: (data.cidr0_cidrs || []).map(c => `${c.v4prefix || c.v6prefix}/${c.length}`),
      status: data.status,
      created: events.registration,
      updated: events['last changed'],
      abuseContacts: abuse,
    };
    setCached('rdap-ip', ip, out);
    return out;
  }

  function vcardName(entity) {
    const vcard = (entity.vcardArray && entity.vcardArray[1]) || [];
    const fn = vcard.find(v => v[0] === 'fn');
    return fn ? fn[3] : null;
  }

  function collectAbuseContacts(entity) {
    const out = [];
    const walk = (e) => {
      if ((e.roles || []).includes('abuse')) {
        const vcard = (e.vcardArray && e.vcardArray[1]) || [];
        const email = vcard.find(v => v[0] === 'email');
        if (email) out.push(email[3]);
      }
      (e.entities || []).forEach(walk);
    };
    walk(entity);
    return out;
  }

  // ─── VirusTotal v3 (API key required) ──────────────────────────────────────
  async function vtLookup(type, ioc, apiKey) {
    if (!apiKey) throw new Error('VirusTotal API key not configured');
    const cached = getCached('vt-' + type, ioc);
    if (cached) return cached;
    const path = {
      ipv4: 'ip_addresses',
      ipv6: 'ip_addresses',
      domain: 'domains',
      url: 'urls',
      md5: 'files', sha1: 'files', sha256: 'files',
    }[type];
    if (!path) throw new Error(`VT unsupported type: ${type}`);

    let identifier = ioc;
    if (path === 'urls') {
      // VT wants base64url-encoded URL id
      identifier = urlsafeB64(ioc);
    }
    const url = `https://www.virustotal.com/api/v3/${path}/${encodeURIComponent(identifier)}`;
    const res = await safeFetch(url, { headers: { 'x-apikey': apiKey } });
    if (res.status === 404) {
      const out = { source: 'VirusTotal', notFound: true };
      setCached('vt-' + type, ioc, out);
      return out;
    }
    if (!res.ok) throw new Error(`VT HTTP ${res.status}`);
    const json = await res.json();
    const attrs = json.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const total = (stats.malicious||0) + (stats.suspicious||0) + (stats.undetected||0) + (stats.harmless||0) + (stats.timeout||0);

    // Popular threat classification (files, sometimes URLs/domains)
    const ptc = attrs.popular_threat_classification;
    const threatFamily = ptc?.suggested_threat_label || null;
    const threatCategories = (ptc?.popular_threat_category || []).map(c => c.value);
    const threatFamilies = (ptc?.popular_threat_name || []).map(n => n.value);

    // Sigma / IDS / YARA crowdsourced
    const sigmaHits = (attrs.crowdsourced_sigma_results || []).map(r => ({
      title: r.rule_title, level: r.rule_level, source: r.rule_source, id: r.rule_id,
    }));
    const idsHits = (attrs.crowdsourced_ids_results || []).map(r => ({
      alert: r.alert_context?.[0]?.msg || r.rule_msg, category: r.rule_category, severity: r.alert_severity, source: r.rule_source,
    }));
    const yaraHits = (attrs.crowdsourced_yara_results || []).map(r => ({
      name: r.rule_name, ruleset: r.ruleset_name, source: r.source, author: r.author, description: r.description,
    }));

    // Signature (Authenticode)
    const sig = attrs.signature_info;
    const signature = sig ? {
      verified: sig.verified,
      product: sig.product,
      signers: sig.signers,
      signingDate: sig['signing date'] || sig.signing_date,
      copyright: sig.copyright,
      description: sig.description,
      originalName: sig['original name'] || sig.original_name,
      fileVersion: sig['file version'],
    } : null;

    // Sandbox verdicts (aggregated across sandboxes)
    const sandbox = attrs.sandbox_verdicts ? Object.entries(attrs.sandbox_verdicts).map(([sb, v]) => ({
      sandbox: sb,
      category: v.category,
      confidence: v.confidence,
      malwareClasses: v.malware_classification,
      malwareNames: v.malware_names,
    })) : [];

    // JARM + last HTTPS cert
    const jarm = attrs.jarm || null;
    const cert = attrs.last_https_certificate;
    const httpsCert = cert ? {
      issuer: cert.issuer,
      subject: cert.subject,
      validity: cert.validity,
      san: (cert.extensions && (cert.extensions.subject_alternative_name || cert.extensions['subject_alternative_name'])) || [],
      thumbprint: cert.thumbprint || cert.thumbprint_sha256,
    } : null;

    // Passive DNS from VT (domains)
    const lastDns = (attrs.last_dns_records || []).slice(0, 20).map(r => ({
      type: r.type, ttl: r.ttl, value: r.value,
    }));

    // Categories (per-vendor for domains/URLs, file type for files)
    const categories = attrs.categories || null;

    // Popularity ranks (domains)
    const popularity = attrs.popularity_ranks ? Object.entries(attrs.popularity_ranks).map(([src, v]) => ({
      source: src, rank: v.rank, timestamp: v.timestamp,
    })) : [];

    // URL-specific
    const urlExtras = (type === 'url') ? {
      finalUrl: attrs.last_final_url,
      redirectChain: attrs.redirection_chain,
      threatNames: attrs.threat_names,
      responseCode: attrs.last_http_response_code,
      responseHeaders: attrs.last_http_response_headers,
      title: attrs.title,
    } : null;

    // Network info for IPs
    const ipExtras = (type === 'ipv4' || type === 'ipv6') ? {
      asOwner: attrs.as_owner,
      asn: attrs.asn,
      country: attrs.country,
      continent: attrs.continent,
      network: attrs.network,
      rir: attrs.regional_internet_registry,
    } : null;

    // File-specific extras
    const fileExtras = (type === 'md5' || type === 'sha1' || type === 'sha256') ? {
      md5: attrs.md5,
      sha1: attrs.sha1,
      sha256: attrs.sha256,
      ssdeep: attrs.ssdeep,
      tlsh: attrs.tlsh,
      imphash: attrs.pe_info?.imphash,
      vhash: attrs.vhash,
      size: attrs.size,
      typeTag: attrs.type_tag,
      typeExt: attrs.type_extension,
      magic: attrs.magic,
      timesSubmitted: attrs.times_submitted,
      uniqueSources: attrs.unique_sources,
      creationDate: attrs.creation_date,
      trid: (attrs.trid || []).slice(0, 3),
    } : null;

    // GTI-specific (only present with GTI keys)
    const gti = attrs.gti_assessment ? {
      verdict: attrs.gti_assessment.verdict?.value,
      severity: attrs.gti_assessment.severity?.value,
      threatScore: attrs.gti_assessment.threat_score?.value,
      description: attrs.gti_assessment.description,
    } : null;
    const mandiantScore = attrs.mandiant_ic_score ?? null;

    const out = {
      source: 'VirusTotal',
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total,
      reputation: attrs.reputation,
      tags: attrs.tags || [],
      firstSubmission: attrs.first_submission_date,
      lastAnalysis: attrs.last_analysis_date,
      names: attrs.names,
      typeDesc: attrs.type_description,
      meaningfulName: attrs.meaningful_name,
      totalVotes: attrs.total_votes,
      threatFamily, threatCategories, threatFamilies,
      sigmaHits, idsHits, yaraHits,
      signature,
      sandbox,
      jarm,
      httpsCert,
      lastDns,
      categories,
      popularity,
      urlExtras,
      ipExtras,
      fileExtras,
      gti,
      mandiantScore,
      link: buildVtLink(type, ioc),
    };
    setCached('vt-' + type, ioc, out);
    return out;
  }

  // File behaviour summary (aggregated across sandboxes)
  async function vtBehaviorSummary(hash, apiKey) {
    if (!apiKey) throw new Error('VirusTotal API key not configured');
    const cached = getCached('vt-behavior', hash);
    if (cached) return cached;
    const url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}/behaviour_summary`;
    const res = await safeFetch(url, { headers: { 'x-apikey': apiKey } });
    if (res.status === 404) { const out = { source: 'VT Behavior', notFound: true }; setCached('vt-behavior', hash, out); return out; }
    if (!res.ok) throw new Error(`VT behavior HTTP ${res.status}`);
    const json = await res.json();
    const d = json.data || {};
    const out = {
      source: 'VT Behavior',
      processesCreated: (d.processes_created || []).slice(0, 20),
      processesTerminated: (d.processes_terminated || []).slice(0, 10),
      commandExecutions: (d.command_executions || []).slice(0, 15),
      filesDropped: (d.files_dropped || []).slice(0, 20).map(f => ({ path: f.path, sha256: f.sha256, type: f.type })),
      filesOpened: (d.files_opened || []).slice(0, 15),
      filesWritten: (d.files_written || []).slice(0, 15),
      filesDeleted: (d.files_deleted || []).slice(0, 15),
      registryKeysOpened: (d.registry_keys_opened || []).slice(0, 20),
      registryKeysSet: (d.registry_keys_set || []).slice(0, 20),
      registryKeysDeleted: (d.registry_keys_deleted || []).slice(0, 15),
      mutexesCreated: (d.mutexes_created || []).slice(0, 15),
      dnsLookups: (d.dns_lookups || []).slice(0, 20).map(l => l.hostname).filter(Boolean),
      ipTraffic: (d.ip_traffic || []).slice(0, 20).map(t => t.destination_ip).filter(Boolean),
      httpConversations: (d.http_conversations || []).slice(0, 15).map(h => ({ url: h.url, method: h.request_method, status: h.response_status_code })),
      tags: d.tags || [],
      mitre: d.mitre_attack_techniques || [],
    };
    setCached('vt-behavior', hash, out);
    return out;
  }

  // GTI collections membership (threat actors, malware families, campaigns)
  async function vtCollections(type, ioc, apiKey) {
    if (!apiKey) throw new Error('VirusTotal API key not configured');
    const cached = getCached('vt-collections', `${type}:${ioc}`);
    if (cached) return cached;
    const path = { ipv4: 'ip_addresses', ipv6: 'ip_addresses', domain: 'domains', url: 'urls', md5: 'files', sha1: 'files', sha256: 'files' }[type];
    if (!path) return { source: 'GTI Collections', notFound: true };
    let identifier = ioc;
    if (path === 'urls') identifier = urlsafeB64(ioc);
    const url = `https://www.virustotal.com/api/v3/${path}/${encodeURIComponent(identifier)}/collections?limit=40`;
    const res = await safeFetch(url, { headers: { 'x-apikey': apiKey } });
    if (res.status === 404) { const out = { source: 'GTI Collections', notFound: true }; setCached('vt-collections', `${type}:${ioc}`, out); return out; }
    if (res.status === 403) return { source: 'GTI Collections', error: 'GTI subscription required' };
    if (!res.ok) throw new Error(`VT collections HTTP ${res.status}`);
    const json = await res.json();
    const items = (json.data || []).map(c => ({
      id: c.id,
      name: c.attributes?.name,
      type: c.attributes?.collection_type,
      description: c.attributes?.description,
      threatActors: (c.attributes?.threat_actors || []).map(a => a.value || a),
      malwareFamilies: (c.attributes?.malware_families || []).map(m => m.value || m),
      targetedRegions: c.attributes?.targeted_regions,
      targetedIndustries: c.attributes?.targeted_industries,
      link: `https://www.virustotal.com/gui/collection/${c.id}`,
    }));
    // Group by type for display
    const grouped = {
      threat_actor: items.filter(i => i.type === 'threat-actor'),
      malware_family: items.filter(i => i.type === 'malware-family'),
      campaign: items.filter(i => i.type === 'campaign'),
      report: items.filter(i => i.type === 'report'),
      other: items.filter(i => !['threat-actor', 'malware-family', 'campaign', 'report'].includes(i.type)),
    };
    const out = { source: 'GTI Collections', items, grouped, count: items.length };
    setCached('vt-collections', `${type}:${ioc}`, out);
    return out;
  }

  function buildVtLink(type, ioc) {
    if (type === 'ipv4' || type === 'ipv6') return `https://www.virustotal.com/gui/ip-address/${ioc}`;
    if (type === 'domain') return `https://www.virustotal.com/gui/domain/${ioc}`;
    if (type === 'url') return `https://www.virustotal.com/gui/url/${urlsafeB64(ioc)}`;
    return `https://www.virustotal.com/gui/file/${ioc}`;
  }

  function urlsafeB64(input) {
    const b64 = btoa(unescape(encodeURIComponent(input)));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // ─── AbuseIPDB (free key, 1k/day) ──────────────────────────────────────────
  async function abuseIpdb(ip, apiKey) {
    if (!apiKey) throw new Error('AbuseIPDB API key not configured');
    const cached = getCached('abuseipdb', ip);
    if (cached) return cached;
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const res = await safeFetch(url, {
      headers: { 'Key': apiKey, 'Accept': 'application/json' },
    });
    if (!res.ok) throw new Error(`AbuseIPDB HTTP ${res.status}`);
    const json = await res.json();
    const d = json.data || {};
    const out = {
      source: 'AbuseIPDB',
      confidence: d.abuseConfidenceScore,
      totalReports: d.totalReports,
      lastReportedAt: d.lastReportedAt,
      countryCode: d.countryCode,
      usageType: d.usageType,
      isp: d.isp,
      domain: d.domain,
      isTor: d.isTor,
      isWhitelisted: d.isWhitelisted,
      link: `https://www.abuseipdb.com/check/${ip}`,
    };
    setCached('abuseipdb', ip, out);
    return out;
  }

  // ─── GreyNoise Community (optional free key) ───────────────────────────────
  async function greynoise(ip, apiKey) {
    if (!apiKey) throw new Error('GreyNoise API key not configured');
    const cached = getCached('greynoise', ip);
    if (cached) return cached;
    const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`;
    const res = await safeFetch(url, { headers: { 'key': apiKey, 'Accept': 'application/json' } });
    if (res.status === 404) {
      const out = { source: 'GreyNoise', notFound: true };
      setCached('greynoise', ip, out);
      return out;
    }
    if (!res.ok) throw new Error(`GreyNoise HTTP ${res.status}`);
    const json = await res.json();
    const out = {
      source: 'GreyNoise',
      classification: json.classification,
      name: json.name,
      lastSeen: json.last_seen,
      noise: json.noise,
      riot: json.riot,
      message: json.message,
      link: json.link,
    };
    setCached('greynoise', ip, out);
    return out;
  }

  // ─── Enrichment orchestrator ───────────────────────────────────────────────
  async function enrichIoc(ioc, settings) {
    const type = ioc.type;
    const value = ioc.value;
    const keys = settings.apiKeys || {};
    const behavior = settings.behavior || {};
    const gtiEnabled = !!behavior.gtiEnabled;
    const behaviorEnabled = behavior.vtBehaviorEnabled !== false; // default on for files
    const jobs = [];

    const isHash = type === 'md5' || type === 'sha1' || type === 'sha256';

    if (type === 'ipv4' || type === 'ipv6') {
      jobs.push(['ipApi', ipApi(value)]);
      jobs.push(['rdap', rdapIp(value)]);
      jobs.push(['reverseDns', reverseDns(value).catch(e => ({ error: e.message }))]);
      if (keys.virustotal) {
        jobs.push(['virustotal', vtLookup(type, value, keys.virustotal)]);
        if (gtiEnabled) jobs.push(['gtiCollections', vtCollections(type, value, keys.virustotal)]);
      }
      if (keys.abuseipdb) jobs.push(['abuseipdb', abuseIpdb(value, keys.abuseipdb)]);
      if (keys.greynoise) jobs.push(['greynoise', greynoise(value, keys.greynoise)]);
    } else if (type === 'domain') {
      jobs.push(['forwardDns', forwardDns(value)]);
      jobs.push(['rdap', rdapDomain(value).catch(e => ({ error: e.message }))]);
      if (keys.virustotal) {
        jobs.push(['virustotal', vtLookup('domain', value, keys.virustotal)]);
        if (gtiEnabled) jobs.push(['gtiCollections', vtCollections('domain', value, keys.virustotal)]);
      }
    } else if (type === 'url') {
      if (keys.virustotal) {
        jobs.push(['virustotal', vtLookup('url', value, keys.virustotal)]);
        if (gtiEnabled) jobs.push(['gtiCollections', vtCollections('url', value, keys.virustotal)]);
      }
      try {
        const u = new URL(value);
        if (u.hostname) {
          jobs.push(['hostForwardDns', forwardDns(u.hostname)]);
          jobs.push(['hostRdap', rdapDomain(u.hostname).catch(e => ({ error: e.message }))]);
        }
      } catch (_) {}
    } else if (isHash) {
      if (keys.virustotal) {
        jobs.push(['virustotal', vtLookup(type, value, keys.virustotal)]);
        if (behaviorEnabled) jobs.push(['vtBehavior', vtBehaviorSummary(value, keys.virustotal)]);
        if (gtiEnabled) jobs.push(['gtiCollections', vtCollections(type, value, keys.virustotal)]);
      }
    } else if (type === 'cve') {
      jobs.push(['nvd', nvdLookup(value).catch(e => ({ error: e.message }))]);
    }

    const results = {};
    const settled = await Promise.allSettled(jobs.map(([name, p]) => p.then(v => [name, v])));
    settled.forEach((r, i) => {
      const name = jobs[i][0];
      if (r.status === 'fulfilled') {
        results[name] = r.value[1];
      } else {
        results[name] = { error: r.reason?.message || String(r.reason) };
      }
    });
    return { ioc, results, enrichedAt: Date.now() };
  }

  async function nvdLookup(cve) {
    const cached = getCached('nvd', cve);
    if (cached) return cached;
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve.toUpperCase())}`;
    const res = await safeFetch(url, {}, 15000);
    if (!res.ok) throw new Error(`NVD HTTP ${res.status}`);
    const json = await res.json();
    const item = json.vulnerabilities?.[0]?.cve;
    if (!item) return { source: 'NVD', notFound: true };
    const metric = item.metrics?.cvssMetricV31?.[0]?.cvssData
                 || item.metrics?.cvssMetricV30?.[0]?.cvssData
                 || item.metrics?.cvssMetricV2?.[0]?.cvssData;
    const out = {
      source: 'NVD',
      id: item.id,
      published: item.published,
      lastModified: item.lastModified,
      description: (item.descriptions?.find(d => d.lang === 'en') || {}).value,
      cvssScore: metric?.baseScore,
      cvssVector: metric?.vectorString,
      severity: metric?.baseSeverity,
      link: `https://nvd.nist.gov/vuln/detail/${item.id}`,
    };
    setCached('nvd', cve, out);
    return out;
  }

  root.SOCEnrichment = {
    enrichIoc,
    ipApi, forwardDns, reverseDns, rdapDomain, rdapIp,
    vtLookup, vtBehaviorSummary, vtCollections,
    abuseIpdb, greynoise, nvdLookup,
  };
})(typeof self !== 'undefined' ? self : globalThis);
