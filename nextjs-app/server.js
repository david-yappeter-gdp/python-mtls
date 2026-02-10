const { createServer } = require('node:https');
const { parse } = require('node:url');
const next = require('next');
const fs = require('node:fs');
const path = require('node:path');

const dev = process.env.NODE_ENV !== 'production';
const hostname = process.env.HOSTNAME || 'localhost';
const port = process.env.PORT || 3000;

// Path to certificates from environment variables
const certPath = process.env.NEXTJS_CERT_PATH || path.join(__dirname, '..', 'certs', 'proxy.crt');
const keyPath = process.env.NEXTJS_KEY_PATH || path.join(__dirname, '..', 'certs', 'proxy.key');
const caPath = process.env.NEXTJS_CA_CERT_PATH || path.join(__dirname, '..', 'certs', 'ca.crt');

const httpsOptions = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
  ca: fs.readFileSync(caPath),
  // Optional: Enable client certificate verification
  requestCert: process.env.NEXTJS_REQUEST_CERT === 'true',
  rejectUnauthorized: process.env.NEXTJS_REJECT_UNAUTHORIZED === 'true',
};

const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

app.prepare().then(() => {
  createServer(httpsOptions, async (req, res) => {
    try {
      const parsedUrl = parse(req.url, true);
      await handle(req, res, parsedUrl);
    } catch (err) {
      console.error('Error occurred handling', req.url, err);
      res.statusCode = 500;
      res.end('internal server error');
    }
  })
    .once('error', (err) => {
      console.error(err);
      process.exit(1);
    })
    .listen(port, () => {
      console.log(`> Ready on https://${hostname}:${port}`);
      console.log(`> Certificate: ${certPath}`);
      console.log(`> Private Key: ${keyPath}`);
      console.log(`> CA Certificate: ${caPath}`);
      console.log(`> Request Client Cert: ${process.env.NEXTJS_REQUEST_CERT || 'false'}`);
    });
});
