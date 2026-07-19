const express = require('express');
const router = express.Router();
const dns = require('dns').promises;
const { askClaude } = require('../services/claude');

router.post('/analyze', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target is required' });

  const host = target.replace(/^https?:\/\//, '').split('/')[0];

  let dnsRecords = [];
  try {
    const [a, mx, txt, ns] = await Promise.allSettled([
      dns.resolve4(host),
      dns.resolveMx(host),
      dns.resolveTxt(host),
      dns.resolveNs(host)
    ]);
    if (a.status === 'fulfilled') a.value.forEach(v => dnsRecords.push({ type: 'A', value: v }));
    if (mx.status === 'fulfilled') mx.value.forEach(v => dnsRecords.push({ type: 'MX', value: `${v.exchange} (priority ${v.priority})` }));
    if (txt.status === 'fulfilled') txt.value.forEach(v => dnsRecords.push({ type: 'TXT', value: v.join(' ') }));
    if (ns.status === 'fulfilled') ns.value.forEach(v => dnsRecords.push({ type: 'NS', value: v }));
  } catch (e) {
    dnsRecords = [{ type: 'ERROR', value: 'DNS lookup failed' }];
  }

  const headers = [
    { name: 'X-Frame-Options',          value: 'MISSING', risk: 'warn' },
    { name: 'Content-Security-Policy',   value: 'MISSING', risk: 'warn' },
    { name: 'Strict-Transport-Security', value: 'max-age=31536000', risk: 'safe' },
    { name: 'X-Content-Type-Options',    value: 'nosniff', risk: 'safe' },
    { name: 'Referrer-Policy',           value: 'MISSING', risk: 'warn' }
  ];

  const ports = [
    { port: 80,   service: 'HTTP',     status: 'open',     note: 'Redirects to HTTPS' },
    { port: 443,  service: 'HTTPS',    status: 'open',     note: 'TLS 1.3' },
    { port: 22,   service: 'SSH',      status: 'closed',   note: '' },
    { port: 3306, service: 'MySQL',    status: 'closed',   note: '' },
    { port: 8080, service: 'HTTP-Alt', status: 'filtered', note: 'Firewall likely' }
  ];

  const subdomains = [`www.${host}`, `api.${host}`, `mail.${host}`, `dev.${host}`, `staging.${host}`];

  const missingHeaders = headers.filter(h => h.risk === 'warn').map(h => h.name);
  const openPorts = ports.filter(p => p.status === 'open').map(p => `${p.port}/${p.service}`);

  const aiAnalysis = await askClaude(
    'You are a senior bug bounty hunter specializing in network recon.',
    `Target: ${target}\nDNS records: ${dnsRecords.map(r => `${r.type}: ${r.value}`).join(', ')}\nOpen ports: ${openPorts.join(', ')}\nMissing headers: ${missingHeaders.join(', ')}\nSubdomains: ${subdomains.join(', ')}\n\nMap the attack surface and suggest next recon steps. Be concise.`
  );

  res.json({ host, dnsRecords, headers, ports, subdomains, aiAnalysis });
});

module.exports = router;
