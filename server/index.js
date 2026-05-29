/**
 * VisionGuard Backend Server
 * 
 * 海康互联开放平台代理服务 + 前端静态文件服务
 * 
 * 启动: npm start
 * 访问: http://localhost:3001
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const fetch = require('node-fetch').default;

const app = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ──────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── 海康互联配置 ────────────────────────────────────────────
let hkConfig = { appKey: '', appSecret: '' };
let appAccessToken = '';
let tokenExpireTime = 0;
const API_BASE = 'https://open-api.hikiot.com';

// ── RSA 工具 ────────────────────────────────────────────────
function loadPublicKeyFromPrivate(pem) {
  const priv = crypto.createPrivateKey({ key: pem, format: 'pem', type: 'pkcs1' });
  const pubJwk = priv.export({ format: 'jwk' });
  return crypto.createPublicKey({ key: { kty: 'RSA', n: pubJwk.n, e: pubJwk.e }, format: 'jwk' });
}

function rsaEncrypt(content, privateKeyPem) {
  const pubKey = loadPublicKeyFromPrivate(privateKeyPem);
  const encrypted = crypto.publicEncrypt(
    { key: pubKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.from(content, 'utf8')
  );
  return encrypted.toString('base64');
}

function rsaDecrypt(encryptedData, privateKeyPem) {
  const privKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem', type: 'pkcs1' });
  const decrypted = crypto.privateDecrypt(
    { key: privKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.from(encryptedData, 'base64')
  );
  return decrypted.toString('utf8');
}

function rsaSign(content, privateKeyPem) {
  const privKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem', type: 'pkcs1' });
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(content);
  return signer.sign(privKey, 'base64');
}

// ── Token管理 ──────────────────────────────────────────────
async function getAppToken() {
  if (appAccessToken && Date.now() < tokenExpireTime) return appAccessToken;
  
  const { appKey, appSecret } = hkConfig;
  if (!appKey || !appSecret) throw new Error('未配置AppKey和AppSecret');

  const authRes = await fetch(`${API_BASE}/auth/v1/third/applyAuthCode`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ appKey }),
  });
  const authData = await authRes.json();
  if (authData.code !== 0) throw new Error(`申请授权码失败: ${authData.msg}`);
  
  const { authCode } = authData.data;
  const signature = rsaSign(`${appKey}${authCode}`, appSecret);
  
  const tokenRes = await fetch(`${API_BASE}/auth/v1/exchangeAppToken`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ appKey, authCode, signature }),
  });
  const tokenData = await tokenRes.json();
  if (tokenData.code !== 0) throw new Error(`获取Token失败: ${tokenData.msg}`);
  
  appAccessToken = tokenData.data.accessToken;
  tokenExpireTime = Date.now() + (tokenData.data.expireIn - 300) * 1000;
  return appAccessToken;
}

// ── API调用 ────────────────────────────────────────────────
async function callHikAPI(endpoint, body = {}) {
  const token = await getAppToken();
  const { appKey, appSecret } = hkConfig;
  
  const bodyStr = JSON.stringify(body);
  const encryptedBody = rsaEncrypt(bodyStr, appSecret);
  
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'App-Access-Token': token,
      'App-Key': appKey,
    },
    body: JSON.stringify({ bodySecret: encryptedBody }),
  });
  
  const result = await res.json();
  if (result.data && typeof result.data === 'string') {
    try { result.data = JSON.parse(rsaDecrypt(result.data, appSecret)); } catch (e) {}
  }
  return result;
}

// ════════════════════════════════════════════════════════════
//  API 路由
// ════════════════════════════════════════════════════════════

app.get('/api/hikconnect/health', (_req, res) => {
  res.json({
    status: 'ok',
    platform: 'hikconnect',
    configured: !!(hkConfig.appKey && hkConfig.appSecret)
  });
});

app.post('/api/hikconnect/config', (req, res) => {
  const { appKey, appSecret } = req.body;
  if (!appKey || !appSecret) {
    return res.status(400).json({ code: 'PARAM_ERROR', msg: 'appKey和appSecret均为必填项' });
  }
  hkConfig = { appKey, appSecret };
  appAccessToken = '';
  tokenExpireTime = 0;
  res.json({ code: 'SUCCESS', msg: '配置已保存' });
});

app.get('/api/hikconnect/config', (_req, res) => {
  res.json({
    appKey: hkConfig.appKey,
    configured: !!(hkConfig.appKey && hkConfig.appSecret)
  });
});

app.post('/api/hikconnect/test-connection', async (_req, res) => {
  try {
    await getAppToken();
    res.json({ code: 'SUCCESS', msg: '连接成功' });
  } catch (err) {
    res.json({ code: 'FAILED', msg: err.message });
  }
});

app.post('/api/hikconnect/devices', async (req, res) => {
  try {
    const { pageNo = 1, pageSize = 50 } = req.body;
    const result = await callHikAPI('/device/v1/page', { pageNo, pageSize });
    
    if (result.code === 0 && result.data) {
      const devices = (result.data.list || []).map(d => ({
        id: d.deviceSerial,
        deviceSerial: d.deviceSerial,
        name: d.deviceName || '未命名',
        status: d.status === 1 ? 'online' : 'offline',
        model: d.model || '',
        channelNo: d.channelNo || 1,
        is4G: d.is4G === 1,
      }));
      res.json({ code: 'SUCCESS', data: { list: devices, total: result.data.total || 0 } });
    } else {
      res.json({ code: 'FAILED', msg: result.msg || '获取设备失败' });
    }
  } catch (err) {
    res.status(500).json({ code: 'ERROR', msg: err.message });
  }
});

app.post('/api/hikconnect/device-token', async (req, res) => {
  try {
    const { deviceSerial, channelNo = 1 } = req.body;
    if (!deviceSerial) return res.status(400).json({ code: 'PARAM_ERROR', msg: 'deviceSerial不能为空' });
    
    const result = await callHikAPI('/device/v1/token/ops/get', { deviceSerial, channelNo });
    if (result.code === 0 && result.data) {
      res.json({ code: 'SUCCESS', data: result.data });
    } else {
      res.json({ code: 'FAILED', msg: result.msg || '获取Token失败' });
    }
  } catch (err) {
    res.status(500).json({ code: 'ERROR', msg: err.message });
  }
});

app.post('/api/hikconnect/stream-url', async (req, res) => {
  try {
    const { deviceSerial, channelNo = 1, protocol = 'hls' } = req.body;
    if (!deviceSerial) return res.status(400).json({ code: 'PARAM_ERROR', msg: 'deviceSerial不能为空' });
    
    const result = await callHikAPI('/video/v1/stream/url', { deviceSerial, channelNo, protocol });
    if (result.code === 0 && result.data?.url) {
      res.json({ code: 'SUCCESS', data: { url: result.data.url, deviceSerial, channelNo } });
    } else {
      res.json({ code: 'FAILED', msg: result.msg || '获取流地址失败' });
    }
  } catch (err) {
    res.status(500).json({ code: 'ERROR', msg: err.message });
  }
});

app.post('/api/hikconnect/ptz', async (req, res) => {
  try {
    const { deviceSerial, channelNo = 1, command, action, speed = 50 } = req.body;
    const result = await callHikAPI('/video/v1/ptz/control', {
      deviceSerial, channelNo, command, action, speed
    });
    if (result.code === 0) {
      res.json({ code: 'SUCCESS', msg: '云台控制成功' });
    } else {
      res.json({ code: 'FAILED', msg: result.msg });
    }
  } catch (err) {
    res.status(500).json({ code: 'ERROR', msg: err.message });
  }
});

// ════════════════════════════════════════════════════════════
//  前端静态文件服务
// ════════════════════════════════════════════════════════════

// 尝试多个可能的路径找 dist 目录
function findDistPath() {
  const candidates = [
    path.join(__dirname, '..', 'dist'),
    path.join(__dirname, 'dist'),
    path.join(process.cwd(), 'dist'),
  ];
  
  for (const p of candidates) {
    if (fs.existsSync(p) && fs.existsSync(path.join(p, 'index.html'))) {
      console.log(`  ✓ 找到前端文件: ${p}`);
      return p;
    }
  }
  return null;
}

const distPath = findDistPath();

if (distPath) {
  app.use(express.static(distPath));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
} else {
  // 如果没有找到 dist 目录，显示引导页面
  app.get('/', (_req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>VisionGuard 服务器</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #0c0d12; color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 20px;
    }
    .box {
      max-width: 560px; width: 100%;
      background: #151620; border: 1px solid rgba(255,255,255,0.06);
      border-radius: 12px; padding: 40px;
    }
    .logo { font-size: 24px; font-weight: 600; color: #fff; margin-bottom: 8px; }
    .status { display: inline-flex; align-items: center; gap: 6px;
      background: rgba(0,230,118,0.1); color: #00e676;
      padding: 4px 12px; border-radius: 20px; font-size: 13px; margin-bottom: 24px; }
    h2 { font-size: 16px; color: #fff; margin: 24px 0 12px; }
    p { font-size: 14px; color: #94a3b8; line-height: 1.7; margin-bottom: 8px; }
    code {
      background: rgba(255,255,255,0.06); padding: 2px 8px;
      border-radius: 4px; font-family: 'Consolas', monospace; font-size: 13px; color: #e2e8f0;
    }
    .file-tree {
      background: rgba(0,0,0,0.3); padding: 16px 20px;
      border-radius: 8px; font-family: 'Consolas', monospace;
      font-size: 13px; line-height: 1.8; color: #94a3b8; margin: 12px 0;
    }
    .file-tree .dir { color: #60a5fa; }
    .file-tree .file { color: #94a3b8; }
    .warn { background: rgba(255,179,0,0.08); border: 1px solid rgba(255,179,0,0.2);
      padding: 12px 16px; border-radius: 8px; color: #ffb300; font-size: 13px; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="box">
    <div class="logo">VisionGuard 服务器</div>
    <span class="status">运行中</span>
    
    <h2>API 服务正常</h2>
    <p>后端服务已成功启动，API 接口可以正常响应。</p>
    <p>但 <strong>dist</strong>（前端网页文件）目录未找到，所以无法显示网页界面。</p>
    
    <h2>解决方法</h2>
    <p>请确保文件结构如下（<strong>dist</strong> 和 <strong>server</strong> 在同一层级）：</p>
    <div class="file-tree">
<span class="dir">app/</span><br>
├── <span class="dir">dist/</span>          &lt;-- 前端文件（index.html 等）<br>
│   ├── index.html<br>
│   └── assets/<br>
└── <span class="dir">server/</span>        &lt;-- 后端文件<br>
    ├── index.js<br>
    └── package.json
    </div>
    
    <p>当前 <strong>server</strong> 目录位置：</p>
    <code>${__dirname}</code>
    
    <div class="warn">
      请将 <strong>dist</strong> 文件夹复制到 server 同级目录下，然后刷新本页面。
    </div>
    
    <h2>或者直接访问远程网站</h2>
    <p>保持此窗口运行，然后访问远程部署的网站也可以调用本地 API。</p>
    <p>但由于浏览器安全限制（HTTPS 不能访问 HTTP），建议把 dist 放到正确位置后访问 <code>http://localhost:3001</code>。</p>
  </div>
</body>
</html>`);
  });
}

// ════════════════════════════════════════════════════════════
//  启动
// ════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║     VisionGuard 服务器启动成功！         ║');
  console.log('╠══════════════════════════════════════════╣');
  console.log(`║  访问地址: http://localhost:${PORT}         ║`);
  if (!distPath) {
    console.log('║                                          ║');
    console.log('║  ⚠️  未找到 dist 目录                     ║');
    console.log('║     请将 dist 文件夹复制到 server 同级   ║');
  }
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
});
