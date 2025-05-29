export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const crypto = require('crypto');

  const {
    url,
    method,
    consumerKey,
    consumerSecret,
    token,
    tokenSecret,
    realm = '',
    extraParams = {}
  } = req.body;

  if (!url || !method || !consumerKey || !consumerSecret || !token || !tokenSecret) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_token: token,
    oauth_nonce: crypto.randomBytes(16).toString('hex'),
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_signature_method: 'HMAC-SHA256',
    oauth_version: '1.0',
    ...extraParams
  };

  const paramString = Object.entries(oauthParams)
    .sort()
    .map(([k, v]) => \`\${encodeURIComponent(k)}=\${encodeURIComponent(v)}\`)
    .join('&');

  const baseString = [
    method.toUpperCase(),
    encodeURIComponent(url),
    encodeURIComponent(paramString)
  ].join('&');

  const signingKey = \`\${encodeURIComponent(consumerSecret)}&\${encodeURIComponent(tokenSecret)}\`;

  const signature = crypto
    .createHmac('sha256', signingKey)
    .update(baseString)
    .digest('base64');

  const header = \`OAuth realm="\${realm}", \` +
    Object.entries(oauthParams)
      .map(([k, v]) => \`\${encodeURIComponent(k)}="\${encodeURIComponent(v)}"\`)
      .join(', ') +
    \`, oauth_signature="\${encodeURIComponent(signature)}"\`;

  res.status(200).json({ authorizationHeader: header });
}
