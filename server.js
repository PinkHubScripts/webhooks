const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage: { key: [ { method, headers, body, date }, ... ] }
const webhookData = {};

app.use(bodyParser.raw({ type: '*/*' })); // capture raw body for any content type
app.use(express.static('public'));        // serve static frontend

// Generate a new webhook key
app.post('/generate', (req, res) => {
  const key = crypto.randomBytes(16).toString('hex');
  webhookData[key] = [];
  res.json({ key, webhookUrl: `/webhook/${key}`, viewUrl: `/view/${key}` });
});

// Receive webhook POST requests
app.all('/webhook/:key', (req, res) => {
  const { key } = req.params;
  if (!webhookData[key]) {
    return res.status(404).send('Webhook key not found');
  }

  const entry = {
    method: req.method,
    headers: req.headers,
    body: req.body.toString('utf8'), // raw body as string
    timestamp: new Date().toISOString()
  };
  webhookData[key].push(entry);

  console.log(`Received webhook for ${key}:`, entry);
  res.status(200).send('Webhook received');
});

// View received webhooks for a key (HTML page)
app.get('/view/:key', (req, res) => {
  const { key } = req.params;
  const data = webhookData[key] || [];
  res.send(`
    <html>
      <head><title>Webhook Data for ${key}</title></head>
      <body>
        <h1>Webhook Data for ${key}</h1>
        <p><a href="/">← Generate another</a></p>
        <pre>${JSON.stringify(data, null, 2)}</pre>
      </body>
    </html>
  `);
});

// Optional: raw JSON endpoint for programmatic access
app.get('/api/webhook/:key', (req, res) => {
  const { key } = req.params;
  res.json(webhookData[key] || []);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
