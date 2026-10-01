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
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`;
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

  // ─── ProxyCheck.io (free key, 1k/day) ──────────────────────────────────────
  async function proxycheck(ip, apiKey) {
    const cached = getCached('proxycheck', ip);
    if (cached) return cached;
    const url = `https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7${apiKey ? '&key=' + encodeURIComponent(apiKey) : ''}`;
    const res = await safeFetch(url);
    if (!res.ok) throw new Error(`ProxyCheck HTTP ${res.status}`);
    const json = await res.json();
    if (json.status && json.status !== 'ok' && json.status !== 'warning') throw new Error(json.message || 'ProxyCheck error');
    const d = json[ip] || {};
    const out = {
      source: 'ProxyCheck',
      proxy: d.proxy === 'yes',
      vpn: d.type === 'VPN',
      type: d.type,
      riskScore: d.risk,
      country: d.country,
      city: d.city,
      asn: d.asn,
      provider: d.provider,
      organisation: d.organisation,
      lastSeen: d['last seen'],
      link: `https://proxycheck.io/v2/${ip}`,
    };
    setCached('proxycheck', ip, out);
    return out;
  }

  // ─── IPInfo.io (free token, 50k/mo) ────────────────────────────────────────
  async function ipinfo(ip, token) {
    if (!token) throw new Error('IPInfo token not configured');
    const cached = getCached('ipinfo', ip);
    if (cached) return cached;
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(token)}`;
    const res = await safeFetch(url);
    if (!res.ok) throw new Error(`IPInfo HTTP ${res.status}`);
    const d = await res.json();
    const out = {
      source: 'IPInfo',
      city: d.city, region: d.region, country: d.country,
      loc: d.loc, timezone: d.timezone,
      org: d.org, hostname: d.hostname,
      asn: d.asn, company: d.company, abuse: d.abuse,
      privacy: d.privacy, // vpn/proxy/tor/relay/hosting flags (paid plans only)
      link: `https://ipinfo.io/${ip}`,
    };
    setCached('ipinfo', ip, out);
    return out;
  }

  // ─── Shodan (paid key) ─────────────────────────────────────────────────────
  async function shodan(ip, apiKey) {
    if (!apiKey) throw new Error('Shodan API key not configured');
    const cached = getCached('shodan', ip);
    if (cached) return cached;
    const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`;
    const res = await safeFetch(url);
    if (res.status === 404) { const out = { source: 'Shodan', notFound: true }; setCached('shodan', ip, out); return out; }
    if (!res.ok) throw new Error(`Shodan HTTP ${res.status}`);
    const d = await res.json();
    const out = {
      source: 'Shodan',
      ports: d.ports,
      hostnames: d.hostnames,
      os: d.os,
      isp: d.isp, org: d.org,
      asn: d.asn,
      country: d.country_name, city: d.city,
      tags: d.tags,
      vulns: d.vulns, // array of CVEs
      lastUpdate: d.last_update,
      services: (d.data || []).slice(0, 10).map(s => ({ port: s.port, product: s.product, version: s.version, module: s._shodan?.module })),
      link: `https://www.shodan.io/host/${ip}`,
    };
    setCached('shodan', ip, out);
    return out;
  }

  // ─── AlienVault OTX (free key) ─────────────────────────────────────────────
  async function otx(type, ioc, apiKey) {
    if (!apiKey) throw new Error('OTX API key not configured');
    const cached = getCached('otx-' + type, ioc);
    if (cached) return cached;
    const otxType = {
      ipv4: 'IPv4', ipv6: 'IPv6', domain: 'domain', url: 'url',
      md5: 'file', sha1: 'file', sha256: 'file',
    }[type];
    if (!otxType) throw new Error(`OTX unsupported type: ${type}`);
    const url = `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/general`;
    const res = await safeFetch(url, { headers: { 'X-OTX-API-KEY': apiKey } });
    if (res.status === 404) { const out = { source: 'AlienVault OTX', notFound: true }; setCached('otx-' + type, ioc, out); return out; }
    if (!res.ok) throw new Error(`OTX HTTP ${res.status}`);
    const d = await res.json();
    const pulses = d.pulse_info?.pulses || [];
    const out = {
      source: 'AlienVault OTX',
      pulseCount: d.pulse_info?.count || 0,
      pulses: pulses.slice(0, 5).map(p => ({
        name: p.name, author: p.author?.username || p.author_name,
        tags: p.tags, created: p.created, references: (p.references || []).slice(0, 3),
        id: p.id,
      })),
      reputation: d.reputation,
      country: d.country_name, city: d.city,
      asn: d.asn,
      link: `https://otx.alienvault.com/indicator/${otxType.toLowerCase()}/${ioc}`,
    };
    setCached('otx-' + type, ioc, out);
    return out;
  }

  // ─── URLScan.io (free key) ─────────────────────────────────────────────────
  async function urlscan(type, ioc, apiKey) {
    if (!apiKey) throw new Error('URLScan API key not configured');
    const cached = getCached('urlscan-' + type, ioc);
    if (cached) return cached;
    let q;
    if (type === 'domain') q = `domain:${ioc}`;
    else if (type === 'url') q = `page.url.keyword:"${ioc.replace(/"/g, '\\"')}"`;
    else if (type === 'ipv4' || type === 'ipv6') q = `page.ip:${ioc}`;
    else throw new Error(`URLScan unsupported type: ${type}`);
    const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=10`;
    const res = await safeFetch(url, { headers: { 'API-Key': apiKey } });
    if (!res.ok) throw new Error(`URLScan HTTP ${res.status}`);
    const d = await res.json();
    const results = (d.results || []).map(r => ({
      time: r.task?.time, url: r.task?.url, domain: r.page?.domain,
      ip: r.page?.ip, country: r.page?.country, status: r.page?.status,
      malicious: r.verdicts?.overall?.malicious,
      score: r.verdicts?.overall?.score,
      categories: r.verdicts?.overall?.categories,
      tags: r.verdicts?.overall?.tags,
      scanId: r._id,
      resultLink: r.result,
      screenshot: r.screenshot,
    }));
    const malicious = results.some(r => r.malicious);
    const out = {
      source: 'URLScan',
      total: d.total,
      malicious,
      recent: results.slice(0, 5),
      link: `https://urlscan.io/search/#${encodeURIComponent(q)}`,
    };
    setCached('urlscan-' + type, ioc, out);
    return out;
  }

  // ─── CrowdSec CTI (free key) ───────────────────────────────────────────────
  async function crowdsec(ip, apiKey) {
    if (!apiKey) throw new Error('CrowdSec API key not configured');
    const cached = getCached('crowdsec', ip);
    if (cached) return cached;
    const url = `https://cti.api.crowdsec.net/v2/smoke/${encodeURIComponent(ip)}`;
    const res = await safeFetch(url, { headers: { 'x-api-key': apiKey } });
    if (res.status === 404) { const out = { source: 'CrowdSec', notFound: true }; setCached('crowdsec', ip, out); return out; }
    if (!res.ok) throw new Error(`CrowdSec HTTP ${res.status}`);
    const d = await res.json();
    const out = {
      source: 'CrowdSec',
      reputation: d.reputation, // malicious / suspicious / known / safe / unknown
      confidence: d.confidence,
      asn: d.as_name,
      asNum: d.as_num,
      country: d.location?.country,
      city: d.location?.city,
      behaviors: (d.behaviors || []).map(b => b.name),
      attackDetails: (d.attack_details || []).slice(0, 5).map(a => a.name),
      scores: d.scores,
      classifications: (d.classifications?.classifications || []).map(c => c.name),
      backgroundNoise: d.background_noise_score,
      firstSeen: d.history?.first_seen,
      lastSeen: d.history?.last_seen,
      link: `https://app.crowdsec.net/cti/${ip}`,
    };
    setCached('crowdsec', ip, out);
    return out;
  }

  // ─── Pulsedive (free key) ──────────────────────────────────────────────────
  async function pulsedive(type, ioc, apiKey) {
    if (!apiKey) throw new Error('Pulsedive API key not configured');
    const cached = getCached('pulsedive-' + type, ioc);
    if (cached) return cached;
    const url = `https://pulsedive.com/api/info.php?indicator=${encodeURIComponent(ioc)}&pretty=1&key=${encodeURIComponent(apiKey)}`;
    const res = await safeFetch(url);
    if (!res.ok) throw new Error(`Pulsedive HTTP ${res.status}`);
    const d = await res.json();
    if (d.error) {
      if (/not found/i.test(d.error)) { const out = { source: 'Pulsedive', notFound: true }; setCached('pulsedive-' + type, ioc, out); return out; }
      throw new Error(d.error);
    }
    const out = {
      source: 'Pulsedive',
      iid: d.iid,
      risk: d.risk, // unknown/none/low/medium/high/critical
      riskRecommended: d.risk_recommended,
      type: d.type,
      threats: (d.threats || []).slice(0, 5).map(t => t.name),
      feeds: (d.feeds || []).slice(0, 5).map(f => ({ name: f.name, category: f.category })),
      stamp_added: d.stamp_added,
      stamp_seen: d.stamp_seen,
      link: d.iid ? `https://pulsedive.com/indicator/?iid=${d.iid}` : `https://pulsedive.com/indicator/?indicator=${encodeURIComponent(ioc)}`,
    };
    setCached('pulsedive-' + type, ioc, out);
    return out;
  }

  // ─── Censys (ID + Secret) ──────────────────────────────────────────────────
  async function censys(ip, apiId, apiSecret) {
    if (!apiId || !apiSecret) throw new Error('Censys API ID + Secret not configured');
    const cached = getCached('censys', ip);
    if (cached) return cached;
    const auth = btoa(`${apiId}:${apiSecret}`);
    const url = `https://search.censys.io/api/v2/hosts/${encodeURIComponent(ip)}`;
    const res = await safeFetch(url, { headers: { 'Authorization': `Basic ${auth}` } });
    if (res.status === 404) { const out = { source: 'Censys', notFound: true }; setCached('censys', ip, out); return out; }
    if (!res.ok) throw new Error(`Censys HTTP ${res.status}`);
    const d = (await res.json()).result || {};
    const out = {
      source: 'Censys',
      services: (d.services || []).slice(0, 10).map(s => ({
        port: s.port,
        protocol: s.service_name,
        banner: s.banner,
        software: (s.software || []).map(sw => `${sw.product}${sw.version ? ' ' + sw.version : ''}`),
      })),
      os: d.operating_system,
      asn: d.autonomous_system?.asn,
      asOrg: d.autonomous_system?.name,
      country: d.location?.country,
      city: d.location?.city,
      lastUpdatedAt: d.last_updated_at,
      dns: d.dns?.reverse_dns?.names,
      link: `https://search.censys.io/hosts/${ip}`,
    };
    setCached('censys', ip, out);
    return out;
  }

  // ─── Hybrid Analysis (free key) ────────────────────────────────────────────
  async function hybridAnalysis(hash, apiKey) {
    if (!apiKey) throw new Error('Hybrid Analysis API key not configured');
    const cached = getCached('hybrid-analysis', hash);
    if (cached) return cached;
    const url = `https://www.hybrid-analysis.com/api/v2/search/hash`;
    const body = new URLSearchParams({ hash });
    const res = await safeFetch(url, {
      method: 'POST',
      headers: {
        'api-key': apiKey,
        'User-Agent': 'Falcon Sandbox',
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });
    if (!res.ok) throw new Error(`Hybrid Analysis HTTP ${res.status}`);
    const arr = await res.json();
    if (!arr.length) { const out = { source: 'Hybrid Analysis', notFound: true }; setCached('hybrid-analysis', hash, out); return out; }
    const r = arr[0];
    const out = {
      source: 'Hybrid Analysis',
      verdict: r.verdict,
      threatScore: r.threat_score,
      threatLevel: r.threat_level, // 0 (no threat) → 2 (malicious)
      threatLabel: r.vx_family || r.classification_tags?.[0],
      environment: r.environment_description,
      submitName: r.submit_name,
      type: r.type_short,
      size: r.size,
      analysisDate: r.analysis_start_time,
      tags: r.tags,
      mitre: (r.mitre_attcks || []).slice(0, 5).map(m => ({ id: m.technique_id, name: m.technique })),
      iocs: {
        hosts: (r.hosts || []).slice(0, 10),
        domains: (r.domains || []).slice(0, 10),
      },
      link: `https://www.hybrid-analysis.com/sample/${hash}`,
    };
    setCached('hybrid-analysis', hash, out);
    return out;
  }

  // ─── Any.Run (free key for public analyses) ────────────────────────────────
  async function anyRun(type, ioc, apiKey) {
    if (!apiKey) throw new Error('Any.Run API key not configured');
    const cached = getCached('anyrun-' + type, ioc);
    if (cached) return cached;
    const url = `https://api.any.run/v1/analysis?search=${encodeURIComponent(ioc)}&limit=5`;
    const res = await safeFetch(url, { headers: { 'Authorization': `API-Key ${apiKey}` } });
    if (!res.ok) throw new Error(`Any.Run HTTP ${res.status}`);
    const d = await res.json();
    const tasks = (d.data?.tasks || d.data || []).slice(0, 5);
    const out = {
      source: 'Any.Run',
      count: tasks.length,
      tasks: tasks.map(t => ({
        uuid: t.uuid,
        verdict: t.verdict,
        threatLevel: t.scores?.verdict?.threatLevel,
        malwareFamily: t.tags?.find(tg => tg.tag?.includes('malware'))?.tag,
        tags: (t.tags || []).map(tg => tg.tag || tg).slice(0, 8),
        mainObject: t.mainObject?.name || t.mainObject?.url,
        link: t.permanentUrl || `https://app.any.run/tasks/${t.uuid}`,
      })),
      link: `https://any.run/report/${encodeURIComponent(ioc)}`,
    };
    setCached('anyrun-' + type, ioc, out);
    return out;
  }

  // ─── FullHunt (free key) ───────────────────────────────────────────────────
  async function fullhunt(type, ioc, apiKey) {
    if (!apiKey) throw new Error('FullHunt API key not configured');
    const cached = getCached('fullhunt-' + type, ioc);
    if (cached) return cached;
    let path;
    if (type === 'domain') path = `domain/${encodeURIComponent(ioc)}/details`;
    else if (type === 'ipv4' || type === 'ipv6') path = `host/${encodeURIComponent(ioc)}`;
    else throw new Error(`FullHunt unsupported type: ${type}`);
    const url = `https://fullhunt.io/api/v1/${path}`;
    const res = await safeFetch(url, { headers: { 'X-API-KEY': apiKey } });
    if (res.status === 404) { const out = { source: 'FullHunt', notFound: true }; setCached('fullhunt-' + type, ioc, out); return out; }
    if (!res.ok) throw new Error(`FullHunt HTTP ${res.status}`);
    const d = await res.json();
    const out = {
      source: 'FullHunt',
      domain: d.domain,
      subdomainsCount: (d.hosts || []).length,
      subdomains: (d.hosts || []).slice(0, 10).map(h => h.host || h),
      ports: d.ports,
      services: d.services,
      cnames: d.cnames,
      tags: d.tags,
      lastSeen: d.last_seen,
      firstSeen: d.first_seen,
      link: type === 'domain' ? `https://fullhunt.io/domain/${ioc}` : `https://fullhunt.io/host/${ioc}`,
    };
    setCached('fullhunt-' + type, ioc, out);
    return out;
  }

  // ─── Polyswarm (free key, hash + URL only) ─────────────────────────────────
  async function polyswarm(type, ioc, apiKey) {
    if (!apiKey) throw new Error('Polyswarm API key not configured');
    const cached = getCached('polyswarm-' + type, ioc);
    if (cached) return cached;
    let path;
    if (type === 'sha256' || type === 'sha1' || type === 'md5') path = `search/hash/${encodeURIComponent(ioc)}`;
    else if (type === 'url') path = `search/url?url=${encodeURIComponent(ioc)}`;
    else throw new Error(`Polyswarm unsupported type: ${type}`);
    const url = `https://api.polyswarm.network/v3/${path}`;
    const res = await safeFetch(url, { headers: { 'Authorization': apiKey } });
    if (res.status === 404) { const out = { source: 'Polyswarm', notFound: true }; setCached('polyswarm-' + type, ioc, out); return out; }
    if (!res.ok) throw new Error(`Polyswarm HTTP ${res.status}`);
    const d = (await res.json()).result || await res.json();
    const first = Array.isArray(d) ? d[0] : d;
    if (!first) { const out = { source: 'Polyswarm', notFound: true }; setCached('polyswarm-' + type, ioc, out); return out; }
    const out = {
      source: 'Polyswarm',
      sha256: first.sha256,
      sha1: first.sha1,
      md5: first.md5,
      mimetype: first.mimetype,
      size: first.size,
      detections: first.detections, // engine results
      firstSeen: first.first_seen,
      lastScanned: first.last_scanned,
      polyscore: first.polyscore,
      metadata: first.metadata,
      link: `https://polyswarm.network/scan/results/${type === 'url' ? 'url' : type}/${encodeURIComponent(ioc)}`,
    };
    setCached('polyswarm-' + type, ioc, out);
    return out;
  }

  // ─── IntelligenceX (free key with limited quota) ───────────────────────────
  async function intelx(ioc, apiKey) {
    if (!apiKey) throw new Error('IntelX API key not configured');
    const cached = getCached('intelx', ioc);
    if (cached) return cached;
    // Step 1: initiate search
    const searchUrl = `https://2.intelx.io/intelligent/search`;
    const searchBody = JSON.stringify({
      term: ioc,
      buckets: [], lookuplevel: 0, maxresults: 20, timeout: 5,
      datefrom: '', dateto: '',
      sort: 2, media: 0, terminate: [],
    });
    const r1 = await safeFetch(searchUrl, {
      method: 'POST',
      headers: { 'x-key': apiKey, 'Content-Type': 'application/json' },
      body: searchBody,
    });
    if (!r1.ok) throw new Error(`IntelX search HTTP ${r1.status}`);
    const { id, status } = await r1.json();
    if (status === 2) { const out = { source: 'IntelligenceX', notFound: true }; setCached('intelx', ioc, out); return out; }
    if (!id) throw new Error('IntelX: no search id returned');
    // Step 2: poll results (small wait, cheap)
    await new Promise(r => setTimeout(r, 1000));
    const resultUrl = `https://2.intelx.io/intelligent/search/result?id=${encodeURIComponent(id)}&limit=20`;
    const r2 = await safeFetch(resultUrl, { headers: { 'x-key': apiKey } });
    if (!r2.ok) throw new Error(`IntelX result HTTP ${r2.status}`);
    const d = await r2.json();
    const records = (d.records || []).slice(0, 10).map(r => ({
      name: r.name,
      bucket: r.bucket,
      added: r.added,
      date: r.date,
      systemId: r.systemid,
      storageId: r.storageid,
      size: r.size,
      type: r.media,
    }));
    const out = {
      source: 'IntelligenceX',
      total: d.records?.length || 0,
      records,
      link: `https://intelx.io/?s=${encodeURIComponent(ioc)}`,
    };
    setCached('intelx', ioc, out);
    return out;
  }

  // ─── Hook new sources into enrichIoc ───────────────────────────────────────
  const _origEnrichIoc = enrichIoc;
  enrichIoc = async function enrichIocWithExtras(ioc, settings) {
    const base = await _origEnrichIoc(ioc, settings);
    const type = ioc.type;
    const value = ioc.value;
    const keys = settings.apiKeys || {};
    const extraJobs = [];

    const isIp = (type === 'ipv4' || type === 'ipv6');
    const isHash = (type === 'md5' || type === 'sha1' || type === 'sha256');

    // IP-only sources
    if (isIp) {
      extraJobs.push(['proxycheck', proxycheck(value, keys.proxycheck).catch(e => ({ error: e.message }))]);
      if (keys.ipinfo) extraJobs.push(['ipinfo', ipinfo(value, keys.ipinfo)]);
      if (keys.shodan) extraJobs.push(['shodan', shodan(value, keys.shodan)]);
      if (keys.crowdsec) extraJobs.push(['crowdsec', crowdsec(value, keys.crowdsec)]);
      if (keys.censys_id && keys.censys_secret) extraJobs.push(['censys', censys(value, keys.censys_id, keys.censys_secret)]);
    }

    // Multi-type: OTX, Pulsedive, Polyswarm
    if (keys.otx && ['ipv4','ipv6','domain','url','md5','sha1','sha256'].includes(type)) {
      extraJobs.push(['otx', otx(type, value, keys.otx)]);
    }
    if (keys.pulsedive && ['ipv4','ipv6','domain','url'].includes(type)) {
      extraJobs.push(['pulsedive', pulsedive(type, value, keys.pulsedive)]);
    }
    if (keys.polyswarm && ['url','md5','sha1','sha256'].includes(type)) {
      extraJobs.push(['polyswarm', polyswarm(type, value, keys.polyswarm)]);
    }

    // Domain/URL/IP: URLScan
    if (keys.urlscan && ['domain','url','ipv4','ipv6'].includes(type)) {
      extraJobs.push(['urlscan', urlscan(type, value, keys.urlscan)]);
    }

    // Domain / IP: FullHunt
    if (keys.fullhunt && ['domain','ipv4','ipv6'].includes(type)) {
      extraJobs.push(['fullhunt', fullhunt(type, value, keys.fullhunt)]);
    }

    // Hash-only: Hybrid Analysis
    if (isHash && keys.hybrid_analysis) {
      extraJobs.push(['hybridAnalysis', hybridAnalysis(value, keys.hybrid_analysis)]);
    }

    // Hash / URL: Any.Run
    if (keys.anyrun && (isHash || type === 'url')) {
      extraJobs.push(['anyrun', anyRun(type, value, keys.anyrun)]);
    }

    // Multi-type including email: IntelX
    if (keys.intelx && ['ipv4','ipv6','domain','url','md5','sha1','sha256','email'].includes(type)) {
      extraJobs.push(['intelx', intelx(value, keys.intelx)]);
    }

    const settled = await Promise.allSettled(extraJobs.map(([name, p]) => p.then(v => [name, v])));
    settled.forEach((r, i) => {
      const name = extraJobs[i][0];
      if (r.status === 'fulfilled') base.results[name] = r.value[1];
      else base.results[name] = { error: r.reason?.message || String(r.reason) };
    });
    return base;
  };

  root.SOCEnrichment = {
    enrichIoc,
    ipApi, forwardDns, reverseDns, rdapDomain, rdapIp,
    vtLookup, vtBehaviorSummary, vtCollections,
    abuseIpdb, greynoise, nvdLookup,
    proxycheck, ipinfo, shodan, otx, urlscan, crowdsec, pulsedive,
    censys, hybridAnalysis, anyRun, fullhunt, polyswarm, intelx,
  };
})(typeof self !== 'undefined' ? self : globalThis);
