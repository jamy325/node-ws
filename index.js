const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');
const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60'; // 运行哪吒v1,在不同的平台需要改UUID,否则会被覆盖       
const DOMAIN = process.env.DOMAIN || '1234.abc.com';       // 填写项目域名或已反代的域名，不带前缀，建议填已反代的域名
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // 节点路径，默认获取uuid前8位
const SUB_PATH = process.env.SUB_PATH || 'sub';            // 获取节点的订阅路径
const NAME = process.env.NAME || '';                       // 节点名称
const PORT = process.env.PORT || 3000;                     // http和ws服务端口

let ISP = '';
const GetISP = async () => {
  try {
    const res = await axios.get('https://api.ip.sb/geoip');
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Unknown';
  }
}
GetISP();

const httpServer = http.createServer((req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const vlessURL = `vless://${UUID}@cdns.doon.eu.org:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const trojanURL = `trojan://${UUID}@cdns.doon.eu.org:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const subscription = vlessURL + '\n' + trojanURL;
    const base64Content = Buffer.from(subscription).toString('base64');
    
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

const wss = new WebSocket.Server({ server: httpServer });
const uuid = UUID.replace(/-/g, "");
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
// Custom DNS
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) {
        reject(new Error(`Failed to resolve ${host} with all DNS servers`));
        return;
      }
      const dnsServer = DNS_SERVERS[attempts];
      attempts++;
      const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
      axios.get(dnsQuery, {
        timeout: 5000,
        headers: {
          'Accept': 'application/dns-json'
        }
      })
      .then(response => {
        const data = response.data;
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          const ip = data.Answer.find(record => record.type === 1);
          if (ip) {
            resolve(ip.data);
            return;
          }
        }
        tryNextDNS();
      })
      .catch(error => {
        tryNextDNS();
      });
    }
    
    tryNextDNS();
  });
}

// VLE-SS处理
function handleVlessConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;
  
  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
    (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));


  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host)
    .then(resolvedIP => {
      net.connect({ host: resolvedIP, port }, function() {
        this.write(msg.slice(i));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', () => {});
    })
    .catch(error => {
      net.connect({ host, port }, function() {
        this.write(msg.slice(i));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', () => {});
    });
  
  return true;
}

// Tro-jan处理
function handleTrojanConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const possiblePasswords = [
      UUID,
    ];
    
    let matchedPassword = null;
    for (const pwd of possiblePasswords) {
      const hash = crypto.createHash('sha224').update(pwd).digest('hex');
      if (hash === receivedPasswordHash) {
        matchedPassword = pwd;
        break;
      }
    }
    
    if (!matchedPassword) return false;
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }
    
    const cmd = msg[offset];
    if (cmd !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => 
        (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else {
      return false;
    }
    
    port = msg.readUInt16BE(offset);
    offset += 2;
    
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }
    
    const duplex = createWebSocketStream(ws);

    resolveHost(host)
      .then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function() {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
        }).on('error', () => {});
      })
      .catch(error => {
        net.connect({ host, port }, function() {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
        }).on('error', () => {});
      });
    
    return true;
  } catch (error) {
    return false;
  }
}
// Ws 连接处理
wss.on('connection', (ws, req) => {
  const url = req.url || '';
  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlessConnection(ws, msg)) {
          ws.close();
        }
        return;
      }
    }

    if (!handleTrojanConnection(ws, msg)) {
      ws.close();
    }
  }).on('error', () => {});
});

httpServer.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
