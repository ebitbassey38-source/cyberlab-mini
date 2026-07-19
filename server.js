const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Routes
app.use('/api/scan', require('./routes/scan'));
app.use('/api/hash', require('./routes/hash'));
app.use('/api/network', require('./routes/network'));
app.use('/api/report', require('./routes/report'));
app.use('/api/takeover', require('./routes/takeover'));

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'Mini CyberLab AI',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`CyberLab Mini running on port ${PORT}`);
});
