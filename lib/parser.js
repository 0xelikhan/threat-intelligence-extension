/*
 * Threat Intelligence: IOC parser
 * Attaches SOCParser to globalThis so it works in content scripts and extension pages.
 */
(function (root) {
  'use strict';

  const PRIVATE_V4_RANGES = [
    [[10, 0, 0, 0], [10, 255, 255, 255]],
    [[172, 16, 0, 0], [172, 31, 255, 255]],
    [[192, 168, 0, 0], [192, 168, 255, 255]],
    [[127, 0, 0, 0], [127, 255, 255, 255]],
    [[169, 254, 0, 0], [169, 254, 255, 255]],
    [[0, 0, 0, 0], [0, 255, 255, 255]],
    [[224, 0, 0, 0], [239, 255, 255, 255]],
    [[100, 64, 0, 0], [100, 127, 255, 255]],
  ];

  const TLD_ALLOWLIST = new Set([
    'com','net','org','io','co','app','dev','me','info','biz','gov','edu','mil',
    'uk','us','ca','de','fr','ru','cn','jp','au','nl','it','es','se','no','fi',
    'ch','be','pl','br','mx','in','za','nz','ie','pt','at','dk','cz','gr','ro',
    'hu','tr','kr','sg','hk','tw','ua','il','ae','sa','th','vn','id','ph','my',
    'xyz','online','site','store','tech','tk','ml','ga','cf','top','icu','click',
    'cloud','ai','sh','tv','fm','cc','pw','pro','one','shop','link','live','life',
    'agency','digital','ninja','systems','solutions','services','academy','world',
  ]);

  const REGEX = {
    ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.|\[\.\]|\(\.\))){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    ipv6: /\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))\b/g,
    md5: /\b[a-fA-F0-9]{32}\b/g,
    sha1: /\b[a-fA-F0-9]{40}\b/g,
    sha256: /\b[a-fA-F0-9]{64}\b/g,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    cve: /\bCVE[-_]\d{4}[-_]\d{4,7}\b/gi,
    mitreTechnique: /\bT\d{4}(?:\.\d{3})?\b/g,
    mitreTactic: /\bTA\d{4}\b/g,
    registry: /\bHK(?:LM|CU|CR|U|CC)(?:\\\\|\\)[A-Za-z0-9\\\-_. ]{3,}/g,
    filepath: /\b[A-Za-z]:\\(?:[^\s"'<>|:*?\r\n]+\\)*[^\s"'<>|:*?\r\n]+/g,
    url: /\b(?:hxxps?|https?):\/\/[^\s"'<>(){}]+/gi,
    domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.\]|\(\.\))){1,}[a-zA-Z]{2,}\b/g,
  };

  function refang(str) {
    return String(str)
      .replace(/\[\.\]/g, '.')
      .replace(/\(\.\)/g, '.')
      .replace(/\[:\]/g, ':')
      .replace(/\[@\]/g, '@')
      .replace(/^hxxps:\/\//i, 'https://')
      .replace(/^hxxp:\/\//i, 'http://');
  }

  function defang(str) {
    return String(str)
      .replace(/^https:\/\//i, 'hxxps://')
      .replace(/^http:\/\//i, 'hxxp://')
      .replace(/\./g, '[.]');
  }

  function isPrivateIPv4(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return false;
    for (const [lo, hi] of PRIVATE_V4_RANGES) {
      let inRange = true;
      for (let i = 0; i < 4; i++) {
        if (parts[i] < lo[i] || parts[i] > hi[i]) { inRange = false; break; }
      }
      if (inRange) return true;
    }
    return false;
  }

  function looksLikeVersion(str) {
    return /^\d+\.\d+\.\d+\.\d+$/.test(str) && str.split('.').some(p => p.length > 3);
  }

  function isSoftwareVersionShape(ip) {
    // Common browser/build version patterns: X.0.0.0 where X is a small-ish integer
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    // X.0.0.0 with X >= 20 (Chrome/Firefox major versions) — real IPs almost never look like this
    if (parts[1] === 0 && parts[2] === 0 && parts[3] === 0 && parts[0] >= 20 && parts[0] <= 999) return true;
    return false;
  }

  function domainHasKnownTLD(domain) {
    const tld = domain.split('.').pop().toLowerCase();
    return TLD_ALLOWLIST.has(tld);
  }

  function extract(text, options = {}) {
    const opts = Object.assign({
      excludePrivateIPs: true,
      requireKnownTLD: true,
    }, options);

    const results = {
      ipv4: new Set(),
      ipv6: new Set(),
      domain: new Set(),
      url: new Set(),
      md5: new Set(),
      sha1: new Set(),
      sha256: new Set(),
      email: new Set(),
      cve: new Set(),
      mitreTechnique: new Set(),
      mitreTactic: new Set(),
      registry: new Set(),
      filepath: new Set(),
    };

    // URLs first — capture before domain scan so we can strip them
    let scratch = text;
    const urlMatches = text.match(REGEX.url) || [];
    urlMatches.forEach(u => {
      const clean = refang(u).replace(/[.,;:!?)\]}]+$/, '');
      results.url.add(clean);
    });
    scratch = scratch.replace(REGEX.url, ' ');

    // Emails before domains (would double-match)
    const emailMatches = scratch.match(REGEX.email) || [];
    emailMatches.forEach(e => results.email.add(e.toLowerCase()));
    scratch = scratch.replace(REGEX.email, ' ');

    // Hashes — SHA256 first, then SHA1, then MD5 to avoid substring collisions
    (text.match(REGEX.sha256) || []).forEach(h => results.sha256.add(h.toLowerCase()));
    const sha256Set = results.sha256;
    (text.match(REGEX.sha1) || []).forEach(h => {
      const low = h.toLowerCase();
      if (![...sha256Set].some(s => s.includes(low))) results.sha1.add(low);
    });
    (text.match(REGEX.md5) || []).forEach(h => {
      const low = h.toLowerCase();
      if (![...sha256Set].some(s => s.includes(low)) &&
          ![...results.sha1].some(s => s.includes(low))) {
        results.md5.add(low);
      }
    });

    // IPv4 — context-aware to reject User-Agent versions like Chrome/154.0.0.0
    const ipRe = new RegExp(REGEX.ipv4.source, 'g');
    let ipMatch;
    while ((ipMatch = ipRe.exec(scratch)) !== null) {
      const start = ipMatch.index;
      const end = start + ipMatch[0].length;
      const before = start > 0 ? scratch[start - 1] : ' ';
      if (before === '/' || before === '\\') continue;
      const preWord = scratch.slice(Math.max(0, start - 20), start);
      if (/\b(?:Chrome|Chromium|Safari|Firefox|Edg|Edge|OPR|Opera|AppleWebKit|Gecko|Trident|Version|MSIE|v)\/\s*$/i.test(preWord)) continue;
      const ip = refang(ipMatch[0]);
      if (looksLikeVersion(ip)) continue;
      if (isSoftwareVersionShape(ip)) continue;
      if (opts.excludePrivateIPs && isPrivateIPv4(ip)) continue;
      results.ipv4.add(ip);
    }

    // IPv6 — skip trivial matches like "::" alone
    (scratch.match(REGEX.ipv6) || []).forEach(ip => {
      if (ip.length >= 3 && ip.includes(':')) results.ipv6.add(ip.toLowerCase());
    });

    // Domains
    (scratch.match(REGEX.domain) || []).forEach(raw => {
      const domain = refang(raw).toLowerCase().replace(/[.,;:!?)\]}]+$/, '');
      if (/^\d+\.\d+$/.test(domain)) return;
      if (/^\d+(\.\d+){3}$/.test(domain)) return; // IP masquerading
      if (opts.requireKnownTLD && !domainHasKnownTLD(domain)) return;
      results.domain.add(domain);
    });

    // Categorical detections
    (text.match(REGEX.cve) || []).forEach(c => results.cve.add(c.toUpperCase().replace(/_/g, '-')));
    (text.match(REGEX.mitreTechnique) || []).forEach(t => results.mitreTechnique.add(t));
    (text.match(REGEX.mitreTactic) || []).forEach(t => results.mitreTactic.add(t));
    (text.match(REGEX.registry) || []).forEach(r => results.registry.add(r));
    (text.match(REGEX.filepath) || []).forEach(p => results.filepath.add(p));

    // Flatten to array-of-IOCs with types
    const flat = [];
    const push = (type, value) => flat.push({ type, value });
    results.ipv4.forEach(v => push('ipv4', v));
    results.ipv6.forEach(v => push('ipv6', v));
    results.domain.forEach(v => push('domain', v));
    results.url.forEach(v => push('url', v));
    results.sha256.forEach(v => push('sha256', v));
    results.sha1.forEach(v => push('sha1', v));
    results.md5.forEach(v => push('md5', v));
    results.email.forEach(v => push('email', v));
    results.cve.forEach(v => push('cve', v));
    results.mitreTechnique.forEach(v => push('mitre_technique', v));
    results.mitreTactic.forEach(v => push('mitre_tactic', v));
    results.registry.forEach(v => push('registry', v));
    results.filepath.forEach(v => push('filepath', v));

    return flat;
  }

  function classify(value) {
    const v = refang(String(value).trim());
    if (REGEX.sha256.test(v)) { REGEX.sha256.lastIndex = 0; return 'sha256'; }
    REGEX.sha256.lastIndex = 0;
    if (REGEX.sha1.test(v)) { REGEX.sha1.lastIndex = 0; return 'sha1'; }
    REGEX.sha1.lastIndex = 0;
    if (REGEX.md5.test(v)) { REGEX.md5.lastIndex = 0; return 'md5'; }
    REGEX.md5.lastIndex = 0;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ipv4';
    if (v.includes(':') && /^[0-9a-fA-F:]+$/.test(v)) return 'ipv6';
    if (/^CVE-\d{4}-\d{4,7}$/i.test(v)) return 'cve';
    if (/^(?:hxxps?|https?):\/\//i.test(value) || /^https?:\/\//i.test(v)) return 'url';
    if (/@/.test(v) && /\./.test(v)) return 'email';
    if (/\./.test(v) && /^[a-zA-Z0-9.\-]+$/.test(v)) return 'domain';
    return 'unknown';
  }

  root.SOCParser = { extract, classify, refang, defang, REGEX, isPrivateIPv4 };
})(typeof self !== 'undefined' ? self : globalThis);
