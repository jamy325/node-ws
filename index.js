#!/usr/bin/env node

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
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       // 哪吒v1填写形式：nz.abc.com:8008   哪吒v0填写形式：nz.abc.com
const NEZHA_PORT = process.env.NEZHA_PORT || '';           // 哪吒v1没有此变量，v0的agent端口为{443,8443,2096,2087,2083,2053}其中之一时开启tls
const NEZHA_KEY = process.env.NEZHA_KEY || '';             // v1的NZ_CLIENT_SECRET或v0的agent端口                
const DOMAIN = process.env.DOMAIN || 'your-domain.com';    // 填写项目域名或已反代的域名，不带前缀，建议填已反代的域名
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      // 是否开启自动访问保活,false为关闭,true为开启,需同时填写DOMAIN变量
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // 节点路径，默认获取uuid前8位
const SUB_PATH = process.env.SUB_PATH || 'sub';            // 获取节点的订阅路径
const NAME = process.env.NAME || '';                       // 节点名称
const PORT = process.env.PORT || 3000;                     // http和ws服务端口

let uuid = UUID.replace(/-/g, ""), CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
   'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

// block speedtest domains
function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = host.toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => {
    return hostLower === blocked || hostLower.endsWith('.' + blocked);
  });
}

async function getisp() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    try {
      const res2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
      const data2 = res2.data;
      ISP = `${data2.countryCode}-${data2.org}`.replace(/ /g, '_');
    } catch (e2) {
      ISP = 'Unknown';
    }
  }
}

async function getip() {
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
      try {
          const res = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
          const ip = res.data.trim();
          CurrentDomain = ip, Tls = 'none', CurrentPort = PORT;
      } catch (e) {
          console.error('Failed to get IP', e.message);
          CurrentDomain = 'cahnge-your-domain.com', Tls = 'tls', CurrentPort = 443;
      }
  } else {
      CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443;
  }
}

// http route
const httpServer = http.createServer(async (req, res) => {
    console.log(`Server recv ${req.url}`);
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
    await getisp();await getip();
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = Tls === 'tls' ? 'tls' : 'none';
    const ssTlsParam = Tls === 'tls' ? 'tls;' : '';
    const vlsURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const troURL = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
    const ssURL = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;
    const subscription = vlsURL + '\n' + troURL + '\n' + ssURL;
    const base64Content = Buffer.from(subscription).toString('base64');

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

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
          console.log("dns error ", error.message)
          tryNextDNS();
        });
    }

    tryNextDNS();
  });
}

// VLE-SS处理
function handleVlsConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;

  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));

  if (isBlockedDomain(host)) {
    ws.close();
    return false;
  }
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host)
    .then(resolvedIP => {
      net.connect({ host: resolvedIP, port }, function () {
        this.write(msg.slice(i));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', (err) => {
        console.error(`handleVlsConnection connect ${resolvedIP} ${port} error `, err.message ? err.message : err);
       });
    })
    .catch(error => {
      net.connect({ host, port }, function () {
        this.write(msg.slice(i));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', (err) => { 
          console.error(`handleVlsConnection connect ${host} ${port} error `, err.message ? err.message : err);
      });
    });

  return true;
}

// Tro-jan处理
function handleTrojConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const possiblePasswords = [UUID];

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
    console.log(`recv ${host}:${port}`)
    if (isBlockedDomain(host)) {
      console.log("blocked")
      ws.close();
      return false;
    }
    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
                  console.log("net.connect ", resolvedIP,port)
        let tcpCon = net.connect({ host: resolvedIP, port }, function () {
                       console.log("net.connected ", resolvedIP,port)

        tcpCon.on('data', (chunk) => console.log('tcp data', chunk.length));
        tcpCon.on('close', (hadError) => console.log('tcp close hadError=', hadError));

          tcpCon.on('end', () => {
            console.log('tcp end')
            if (ws.readyState === ws.OPEN) ws.close(1000, 'upstream end');
          });

          tcpCon.on('close', (hadError) => {
            console.log('tcp error', e.code, e.message)
            if (ws.readyState === ws.OPEN) ws.close(hadError ? 1011 : 1000);
          });

          if (offset < msg.length) {
            let nd = msg.slice(offset)
            this.write(nd);
            console.log("write data", nd)
          }
          duplex.on('error', (err) => {
          console.error(`duplex handleTrojConnection connect ${resolvedIP} ${port} error `, err.message ? err.message : err);
           }).pipe(this).on('error', ( err ) => {
          console.error(`pipe handleTrojConnection connect ${resolvedIP} ${port} error `, err.message ? err.message : err);
            }).pipe(duplex);
        }).on('error', (err) => { 
          console.error(`handleTrojConnection connect ${resolvedIP} ${port} error `, err.message ? err.message : err);
        });


        
      })
      .catch(error => {
                console.log("net.connect 2 ", host,port)
        net.connect({ host, port }, function () {
   console.log("net.connected 2 ", host,port)

          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', (err) => {
          console.error(`duplex handleTrojConnection ${host} ${port} error `, err.message ? err.message : err);
           }).pipe(this).on('error', (err) => { 
          console.error(`pipe handleTrojConnection  ${host} ${port} error `, err.message ? err.message : err);
           }).pipe(duplex);
        }).on('error', (err) => { 
          console.error(`handleTrojConnection connect ${host} ${port} error `, err.message ? err.message : err);
        });
      });

    return true;
  } catch (error) {
    return false;
  }
}

// Ss处理
function handleSsConnection(ws, msg) {
  try {
    let offset = 0;
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
    console.log(`recv ${host}:${port}`)

    if (isBlockedDomain(host)) {
      ws.close();
      return false;
    }
    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
        console.log("net.connect ", resolvedIP,port)

        net.connect({ host: resolvedIP, port }, function () {
          console.log("connected ", resolvedIP, port)
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', (err) => {
              console.log("duplex handleSsConnection error", resolvedIP, port, err)
           }).pipe(this).on('error', (err) => {
                console.log("pipe handleSsConnection error", resolvedIP, port, err)
            }).pipe(duplex);

        }).on('error', (err) => {
           console.error(`handleSsConnection connect ${resolvedIP} ${port} error `, err.message ? err.message : err);
         });
      })
      .catch(error => {
                console.log("net.connect2 ", host,port)

        net.connect({ host, port }, function () {
          console.log("handleSsConnection2 ", resolvedIP, port)

          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', (err) => {
          console.log("duplex handleSsConnection error", host, port, err)
           }).pipe(this).on('error', (err) => { 
          console.log("pipe handleSsConnection error", host, port, err)
           }).pipe(duplex);

        }).on('error', () => { 
            console.error(`handleSsConnection connect ${host} ${port} error `, err.message ? err.message : err);
        });
      });

    return true;
  } catch (error) {
    return false;
  }
}

// Ws handler
const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', (ws, req) => {
  const url = req.url || '';
  console.log("wss url " + url);

  const expectedPath = `/${WSPATH}`;
  if (!url.startsWith(expectedPath)) {
    ws.close();
    return;
  }

  ws.once('message', msg => {
    console.log("ws recv msg ", msg)
    // VLE-SS (version byte 0 + 16 bytes UUID)
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlsConnection(ws, msg)) {
          ws.close();
        }
        return;
      }
    }
    // tro-jan (56 bytes SHA224 hash)
    if (msg.length >= 58) {
      if (handleTrojConnection(ws, msg)) {
        return;
      }
    }
    // SS (ATYP开头: 0x01, 0x03, 0x04)
    if (msg.length > 0 && (msg[0] === 0x01 || msg[0] === 0x03 || msg[0] === 0x04)) {
      if (handleSsConnection(ws, msg)) {
        return;
      }
    }

    ws.close();
  }).on('error', (err) => { 
    console.error("ws on message error ", err)
  });

  const interval = setInterval(() => {
    if (ws.readyState === ws.OPEN) ws.ping();
  }, 1000);


    // 监听错误事件（可选）
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });

  // 监听单个连接的关闭事件
  ws.on('close', (code, reason) => {
    clearInterval(interval)
    console.log(`Connection closed. Code: ${code}, Reason: ${reason.toString()}`);
    // 在这里执行与该连接相关的清理操作
  });

   ws._socket?.on('end',   () => console.log('ws tcp end'));
  ws._socket?.on('close', (hadError) => console.log('ws tcp close hadError=', hadError));
  ws._socket?.on('error', (e) => console.log('ws tcp error', e.code, e.message));

});

const getDownloadUrl = () => {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    if (!NEZHA_PORT) {
      return 'https://arm64.ssss.nyc.mn/v1';
    } else {
      return 'https://arm64.ssss.nyc.mn/agent';
    }
  } else {
    if (!NEZHA_PORT) {
      return 'https://amd64.ssss.nyc.mn/v1';
    } else {
      return 'https://amd64.ssss.nyc.mn/agent';
    }
  }
};

const downloadFile = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;

  try {
    const url = getDownloadUrl();
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream'
    });

    const writer = fs.createWriteStream('npm');
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        console.log('npm download successfully');
        exec('chmod +x npm', (err) => {
          if (err) reject(err);
          resolve();
        });
      });
      writer.on('error', reject);
    });
  } catch (err) {
    throw err;
  }
};

const runnz = async () => {
  try {
    const status = execSync('ps aux | grep -v "grep" | grep "./[n]pm"', { encoding: 'utf-8' });
    if (status.trim() !== '') {
      console.log('npm is already running, skip running...');
      return;
    }
  } catch (e) {
    // 进程不存在时继续运行nezha
  }

  await downloadFile();
  let command = '';
  let tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    const NEZHA_TLS = tlsPorts.includes(NEZHA_PORT) ? '--tls' : '';
    command = `setsid nohup ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const NZ_TLS = tlsPorts.includes(port) ? 'true' : 'false';
      const configYaml = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${NZ_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;

      fs.writeFileSync('config.yaml', configYaml);
    }
    command = `setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &`;
  } else {
    // console.log('NEZHA variable is empty, skip running');
    return;
  }

  try {
    exec(command, { shell: '/bin/bash' }, (err) => {
      if (err) console.error('npm running error:', err);
      else console.log('npm is running');
    });
  } catch (error) {
    console.error(`error: ${error}`);
  }
};


function getCFDownloadUrl() {
       const arch = os.arch();
        if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') 
          return `https://github.com/cloudflare/cloudflared/releases/download/2025.11.1/cloudflared-linux-arm64`
      
      return `https://github.com/cloudflare/cloudflared/releases/download/2025.11.1/cloudflared-linux-amd64`
}

const downloadCF = async () => {
  try {
    const url = getCFDownloadUrl();
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream'
    });

    const writer = fs.createWriteStream('yarn');
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        console.log('yarn download successfully');
        exec('chmod +x yarn', (err) => {
          if (err) reject(err);
          resolve();
        });
      });
      writer.on('error', reject);
    });
  } catch (err) {
    throw err;
  }
};

async function runCF() {
  if (CF_KEY.length < 10) return;

  try {
    const status = execSync('ps aux | grep -v "grep" | grep "./yarn"', { encoding: 'utf-8' });
    if (status.trim() !== '') {
      console.log('yarn is already running, skip running...');
      return;
    }
  } catch (e) {
    console.error("check yarn error",e)
  }

  await downloadCF();

  try{
    let command = "setsid nohup ./yarn tunnel run --token " + CF_KEY;
    exec(command, { shell: '/bin/bash' }, (err) => {
      if (err) console.error('yarn running error:', err);
      else console.log('yarn is running');
    });
  } catch (error) {
    console.error(`error: ${error}`);
  }
}

const delFiles = () => {
  ['npm', 'config.yaml','npx'].forEach(file => fs.unlink(file, () => { }));
};

async function addAccessTask() {
  if (!AUTO_ACCESS) return;

  if (!DOMAIN) {
    return;
  }
  const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
  try {
    const res = await axios.post("https://oooo.serv00.net/add-url", {
      url: fullURL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Automatic Access Task added successfully');
  } catch (error) {
    // console.error('Error adding Task:', error.message);
  }
}

const delFiles = () => {
  ['npm', 'config.yaml'].forEach(file => fs.unlink(file, () => { }));
};

async function readGoole() {

  try {
    const res = await axios.get("https://www.google.com", {headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
    const data2 = res.data;
    console.log('readGoole ', res.status, data2);
  } catch (error) {
    console.error('readGoole :', error.message);
  }

}

httpServer.listen(PORT, () => {
  //readGoole();
  runnz();
  runCF();
  setTimeout(() => {
    delFiles();
  }, 180000);
 // addAccessTask();
  console.log(`Server is running on port ${PORT}`);
});