var API = 'https://cyberlab-mini.onrender.com';
var currentScanType = 'full';
var currentAlgo = 'sha256';

function switchTab(name) {
  document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  document.getElementById('tab-btn-' + name).classList.add('active');
}

function switchHashTab(tab, id) {
  document.querySelectorAll('.hash-content').forEach(function(t) { t.classList.remove('active'); });
  document.querySelectorAll('.hash-tab').forEach(function(t) { t.classList.remove('active'); });
  document.getElementById('hash-' + tab).classList.add('active');
  document.getElementById(id).classList.add('active');
}

function setScanType(type, id) {
  currentScanType = type;
  document.querySelectorAll('.scan-type').forEach(function(b) { b.classList.remove('active'); });
  document.getElementById(id).classList.add('active');
}

function setAlgo(algo, id) {
  currentAlgo = algo;
  document.querySelectorAll('.algo-btn').forEach(function(b) { b.classList.remove('active'); });
  document.getElementById(id).classList.add('active');
}

function show(id, html) { document.getElementById(id).innerHTML = html; }

function loading(id) {
  show(id, '<div class="loading"><div class="spinner"></div>Analyzing with AI...</div>');
}

function aiBox(text) {
  return '<div class="ai-box"><div class="ai-box-header">⚡ AI Analysis</div><div class="ai-box-body">' + text + '</div></div>';
}

function badge(s) { return '<span class="badge badge-' + s + '">' + s + '</span>'; }

function severityColor(s) {
  var c = { critical:'#dc2626', high:'#ea580c', medium:'#d97706', low:'#16a34a', info:'#2563eb' };
  return c[s] || '#2563eb';
}

function post(path, body) {
  return fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function(r) { return r.json(); });
}

function runVulnScan() {
  var target = document.getElementById('vuln-target').value.trim();
  if (!target) { alert('Enter a target URL'); return; }
  loading('vuln-results');
  post('/api/scan/vuln', { target: target, scanType: currentScanType })
    .then(function(data) {
      var html = '<p style="color:#6b7280;font-size:12px;margin-bottom:12px">' + data.findings.length + ' findings</p>';
      data.findings.forEach(function(f) {
        html += '<div class="finding" style="border-left:3px solid ' + severityColor(f.severity) + '">';
        html += '<div class="finding-header">' + badge(f.severity) + ' <strong>' + f.type + '</strong></div>';
        html += '<div class="finding-detail">' + f.detail + '</div>';
        html += '<div class="finding-vector">Vector: ' + f.vector + '</div></div>';
      });
      html += aiBox(data.aiAnalysis);
      window.lastFindings = data.findings;
      document.getElementById('report-btn').style.display = 'block';
      show('vuln-results', html);
      document.getElementById('report-output').style.display = 'none';
    })
    .catch(function(e) { show('vuln-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runHashIdentify() {
  var hash = document.getElementById('hash-input').value.trim();
  if (!hash) { alert('Enter a hash'); return; }
  loading('hash-identify-results');
  post('/api/hash/identify', { hash: hash })
    .then(function(data) {
      var html = '';
      data.matches.forEach(function(m) {
        html += '<div class="card"><div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">';
        html += '<span style="color:#00d4ff;font-weight:700">' + m.name + '</span>';
        html += '<span class="badge ' + (m.crackable ? 'badge-high' : 'badge-low') + '">' + (m.crackable ? 'Crackable' : 'Resistant') + '</span>';
        html += '</div><p style="color:#9ca3af;font-size:12px">' + m.notes + '</p></div>';
      });
      html += aiBox(data.aiAnalysis);
      show('hash-identify-results', html);
    })
    .catch(function(e) { show('hash-identify-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runGenerate() {
  var input = document.getElementById('generate-input').value.trim();
  if (!input) { alert('Enter a string'); return; }
  post('/api/hash/generate', { input: input, algorithm: currentAlgo })
    .then(function(data) {
      show('hash-generate-results', '<div class="code-output"><div class="code-label">' + data.algorithm + ' Hash</div><div class="code-value">' + data.hash + '</div></div>');
    })
    .catch(function(e) { show('hash-generate-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runStrength() {
  var password = document.getElementById('strength-input').value.trim();
  if (!password) { alert('Enter a password'); return; }
  loading('hash-strength-results');
  post('/api/hash/strength', { password: password })
    .then(function(data) {
      var colors = { Weak:'#ef4444', Fair:'#f59e0b', Good:'#22c55e', Strong:'#00d4ff' };
      var color = colors[data.rating] || '#6b7280';
      var pct = (data.score / 7) * 100;
      var html = '<div class="card"><div style="display:flex;justify-content:space-between;margin-bottom:12px">';
      html += '<span style="font-weight:700">Strength: <span style="color:' + color + '">' + data.rating + '</span></span>';
      html += '<span style="color:#6b7280">' + data.score + '/7</span></div>';
      html += '<div class="strength-bar"><div class="strength-fill" style="width:' + pct + '%;background:' + color + '"></div></div>';
      data.checks.forEach(function(c) {
        html += '<div class="check-row"><span class="' + (c.pass ? 'check-pass' : 'check-fail') + '">' + (c.pass ? '✓' : '○') + '</span>';
        html += '<span style="color:' + (c.pass ? '#d1d5db' : '#6b7280') + '">' + c.label + '</span></div>';
      });
      html += '</div>' + aiBox(data.aiAnalysis);
      show('hash-strength-results', html);
    })
    .catch(function(e) { show('hash-strength-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runNetwork() {
  var target = document.getElementById('network-target').value.trim();
  if (!target) { alert('Enter a domain or IP'); return; }
  loading('network-results');
  post('/api/network/analyze', { target: target })
    .then(function(data) {
      var dns = '';
      data.dnsRecords.forEach(function(r) {
        dns += '<div class="dns-row"><span class="dns-type">' + r.type + '</span><span class="dns-value">' + r.value + '</span></div>';
      });
      var hdrs = '';
      data.headers.forEach(function(h) {
        hdrs += '<div class="header-row"><span class="header-name">' + h.name + '</span><span class="' + (h.risk==='safe'?'header-safe':'header-warn') + '">' + h.value + '</span></div>';
      });
      var ports = '';
      data.ports.forEach(function(p) {
        ports += '<div class="port-row"><span class="port-status port-' + p.status + '">' + p.status + '</span><span class="port-num">' + p.port + '</span><span class="port-service">' + p.service + '</span></div>';
      });
      var subs = data.subdomains.map(function(s) { return '<span class="tag">' + s + '</span>'; }).join('');
      var html = '<div class="card"><p class="card-title">DNS Records</p>' + dns + '</div>';
      html += '<div class="card"><p class="card-title">Security Headers</p>' + hdrs + '</div>';
      html += '<div class="card"><p class="card-title">Port Scan</p>' + ports + '</div>';
      html += '<div class="card"><p class="card-title">Subdomains</p><div class="tags">' + subs + '</div></div>';
      html += aiBox(data.aiAnalysis);
      show('network-results', html);
    })
    .catch(function(e) { show('network-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}
/* v2 */

function generateReport() {
  var target = document.getElementById('vuln-target').value.trim();
  var resultsDiv = document.getElementById('vuln-results');
  if (!target) { alert('Run a scan first'); return; }
  if (!window.lastFindings || window.lastFindings.length === 0) { alert('Run a scan first to get findings'); return; }

  var reportDiv = document.getElementById('report-output');
  reportDiv.innerHTML = '<div class="loading"><div class="spinner"></div>Generating HackerOne report with AI...</div>';
  reportDiv.style.display = 'block';

  post('/api/report/generate', { target: target, findings: window.lastFindings })
    .then(function(data) {
      reportDiv.innerHTML = '<div class="ai-box"><div class="ai-box-header">📋 HackerOne Report</div><div class="ai-box-body">' + data.report + '</div></div>';
    })
    .catch(function(e) {
      reportDiv.innerHTML = '<p style="color:#ef4444">Error: ' + e.message + '</p>';
    });
}
