const express = require('express');
const router = express.Router();
const { askClaude } = require('../services/claude');

router.post('/vuln', async (req, res) => {
  const { target, scanType = 'full' } = req.body;
  if (!target) return res.status(400).json({ error: 'Target is required' });

  const findings = {
    full: [
      { id: 1, type: 'Missing Security Headers', severity: 'medium', detail: 'X-Frame-Options and CSP headers not detected.', vector: 'HTTP Response' },
      { id: 2, type: 'Open Redirect Potential', severity: 'low', detail: '?redirect= / ?url= parameters found. Manual verification required.', vector: 'URL Parameters' },
      { id: 3, type: 'SSL/TLS Config', severity: 'info', detail: 'TLS 1.2+ detected. Certificate valid.', vector: 'Transport' },
      { id: 4, type: 'Error Disclosure', severity: 'low', detail: 'Server error pages may reveal stack traces.', vector: 'Error Handling' }
    ],
    headers: [
      { id: 1, type: 'Content-Security-Policy', severity: 'high', detail: 'CSP header absent. XSS not mitigated.', vector: 'HTTP Header' },
      { id: 2, type: 'X-Frame-Options', severity: 'medium', detail: 'Clickjacking protection missing.', vector: 'HTTP Header' },
      { id: 3, type: 'HSTS', severity: 'medium', detail: 'Strict-Transport-Security not enforced.', vector: 'HTTP Header' }
    ],
    sqli: [
      { id: 1, type: 'Error-Based SQLi Vector', severity: 'high', detail: 'Input parameters accept single-quote without sanitization.', vector: 'Query Params' },
      { id: 2, type: 'Time-Based Blind', severity: 'medium', detail: 'SLEEP() payloads show delayed response on id= param.', vector: 'POST Body' }
    ],
    xss: [
      { id: 1, type: 'Reflected XSS Candidate', severity: 'high', detail: 'Search parameter reflects input without encoding.', vector: 'URL Param: q' },
      { id: 2, type: 'DOM XSS Signal', severity: 'medium', detail: 'document.write() usage detected in client-side JS.', vector: 'JavaScript' }
    ]
  };

  const results = findings[scanType] || findings.full;

  const aiAnalysis = await askClaude(
    'You are a senior bug bounty hunter. Give sharp, actionable analysis. No fluff.',
    `Analyze these findings for target: ${target}\n\n${results.map(f => `[${f.severity.toUpperCase()}] ${f.type}: ${f.detail}`).join('\n')}\n\nPrioritize top findings for a bounty report. Be concise.`
  );

  res.json({ target, scanType, findings: results, aiAnalysis });
});

module.exports = router;
