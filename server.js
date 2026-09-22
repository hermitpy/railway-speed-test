// server.js - نسخه کامل با مدیریت تست، لاگ لحظه‌ای و کنترل دستی
const express = require("express");
const axios = require("axios");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { v4: uuidv4 } = require("uuid");
const { spawn, execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const cron = require("node-cron");
const AdmZip = require("adm-zip");

const app = express();
const PORT = process.env.PORT || 3000;

// -------- تنظیمات --------
const CONFIG = {
  configsFile: "./configs.txt",
  remoteConfigUrl: "https://raw.githubusercontent.com/Hmidqorbani/Hmidqorbani/refs/heads/main/mark.txt",
  speedThresholdMbps: 10.0,
  timeoutMs: 30000,
  concurrency: 1,
  outputFile: "./result.txt",
  xrayPath: process.env.XRAY_PATH || "./xray/xray",
  testFileUrls: [
    "http://ipv4.download.thinkbroadband.com/10MB.zip",
    "http://speedtest.tele2.net/10MB.zip",
    "http://speedtest.tele2.net/5MB.zip",
    "https://proof.ovh.net/files/10Mb.dat",
  ],
};

// -------- وضعیت‌های سراسری --------
let isTestRunning = false;
let testStopRequested = false;
let sseClients = [];
let logBuffer = [];

// -------- تابع ارسال لاگ به همه کلاینت‌های SSE --------
function broadcastLog(message, type = "info") {
  const timestamp = new Date().toISOString();
  const logEntry = { timestamp, message, type };
  logBuffer.push(logEntry);
  if (logBuffer.length > 500) logBuffer.shift();

  sseClients.forEach(client => {
    try {
      client.write(`data: ${JSON.stringify(logEntry)}\n\n`);
    } catch (e) {}
  });
}

// -------- تابع لاگ کردن در کنسول و پخش همزمان --------
function logToAll(message, type = "info") {
  console.log(message);
  broadcastLog(message, type);
}

// ============================================================
//  تابع دانلود خودکار Xray-core
// ============================================================

async function downloadXrayIfNeeded() {
  const xrayPath = CONFIG.xrayPath;

  if (fs.existsSync(xrayPath)) {
    logToAll(`✅ Xray-core در مسیر ${xrayPath} موجود است.`, "success");
    try {
      execSync(`chmod +x ${xrayPath}`, { stdio: "ignore" });
    } catch (e) {}
    return true;
  }

  logToAll("📥 Xray-core پیدا نشد، در حال دانلود...", "info");
  try {
    if (!fs.existsSync("./xray")) {
      fs.mkdirSync("./xray", { recursive: true });
    }

    const url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip";
    const response = await axios.get(url, { responseType: "arraybuffer" });

    const zipPath = "./xray.zip";
    fs.writeFileSync(zipPath, response.data);

    const zip = new AdmZip(zipPath);
    zip.extractAllTo("./xray", true);

    fs.unlinkSync(zipPath);

    execSync(`chmod +x ${xrayPath}`, { stdio: "ignore" });

    logToAll(`✅ Xray-core دانلود و در ${xrayPath} نصب شد.`, "success");
    return true;
  } catch (error) {
    logToAll(`❌ خطا در دانلود Xray-core: ${error.message}`, "error");
    return false;
  }
}

// ============================================================
//  تابع دانلود کانفیگ از لینک
// ============================================================

async function downloadConfigs() {
  logToAll(`📥 در حال دانلود کانفیگ از: ${CONFIG.remoteConfigUrl}`, "info");
  try {
    const response = await axios.get(CONFIG.remoteConfigUrl, {
      timeout: 15000,
      headers: { "User-Agent": "Mozilla/5.0" },
    });

    if (response.status === 200 && response.data) {
      if (response.data.trim().length < 10) {
        logToAll("⚠️ فایل کانفیگ دانلود شده خیلی کوچک است.", "warn");
      }
      fs.writeFileSync(CONFIG.configsFile, response.data, "utf8");
      const lines = response.data.split('\n').filter(l => l.trim().length > 0).length;
      logToAll(`✅ کانفیگ با موفقیت دانلود شد (${lines} خط)`, "success");
      return true;
    } else {
      logToAll(`❌ دانلود ناموفق: کد وضعیت ${response.status}`, "error");
      return false;
    }
  } catch (error) {
    logToAll(`❌ خطا در دانلود کانفیگ: ${error.message}`, "error");
    if (fs.existsSync(CONFIG.configsFile)) {
      logToAll("⚠️ از کانفیگ محلی قبلی استفاده می‌شود.", "warn");
      return true;
    } else {
      return false;
    }
  }
}

// ============================================================
//  خواندن کانفیگ از فایل محلی
// ============================================================

function getConfigsFromFile(filePath) {
  if (!fs.existsSync(filePath)) {
    logToAll(`❌ فایل ${filePath} پیدا نشد!`, "error");
    return [];
  }
  const content = fs.readFileSync(filePath, "utf8");
  return content
    .split("\n")
    .map((line) => line.trim())
    .filter(
      (line) => line.length > 0 && /^(vmess|vless|trojan|ss):\/\//i.test(line),
    );
}

// ============================================================
//  استخراج پرچم از نام
// ============================================================

function extractFlagFromName(name) {
  if (!name) return "";
  let decoded = name;
  try {
    decoded = decodeURIComponent(name);
  } catch (e) {}
  const flagRegex = /[\u{1F1E6}-\u{1F1FF}]{2}/u;
  const match = decoded.match(flagRegex);
  if (match) return match[0];
  return "";
}

// ============================================================
//  پارس کردن لینک‌ها (با پشتیبانی کامل از ss)
// ============================================================

function parseLinkToXrayConfig(link, socksPort) {
  // -------- vmess:// --------
  if (link.startsWith("vmess://")) {
    try {
      const base64 = link.substring(8);
      const jsonStr = Buffer.from(base64, "base64").toString("utf-8");
      const parsed = JSON.parse(jsonStr);
      return {
        inbounds: [{ port: socksPort, protocol: "socks", settings: { auth: "noauth", udp: true } }],
        outbounds: [{
          protocol: "vmess",
          settings: {
            vnext: [{
              address: parsed.add,
              port: parseInt(parsed.port),
              users: [{ id: parsed.id, encryption: parsed.scy || "auto", flow: parsed.fp || "", level: 0 }]
            }]
          },
          streamSettings: {
            network: parsed.net || "tcp",
            security: parsed.tls || "",
            tlsSettings: parsed.tls ? { serverName: parsed.sni || "" } : null,
            realitySettings: null,
          }
        }]
      };
    } catch (e) {
      throw new Error(`vmess parse error: ${e.message}`);
    }
  }

  // -------- vless:// --------
  if (link.startsWith("vless://")) {
    try {
      const url = new URL(link);
      const host = url.hostname;
      const port = url.port || 443;
      const id = url.username;
      const params = new URLSearchParams(url.search);
      const encryption = params.get("encryption") || "none";
      const flow = params.get("flow") || "";
      const security = params.get("security") || "";
      const sni = params.get("sni") || host;
      const network = params.get("type") || "tcp";
      const pbk = params.get("pbk") || "";
      const sid = params.get("sid") || "";
      const fp = params.get("fp") || "";

      let streamSettings = { network, security };
      if (security === "reality") {
        streamSettings.realitySettings = { serverName: sni, publicKey: pbk, shortId: sid, fingerprint: fp || "chrome" };
        streamSettings.tlsSettings = null;
      } else if (security) {
        streamSettings.tlsSettings = { serverName: sni };
        streamSettings.realitySettings = null;
      } else {
        streamSettings.tlsSettings = null;
        streamSettings.realitySettings = null;
      }

      return {
        inbounds: [{ port: socksPort, protocol: "socks", settings: { auth: "noauth", udp: true } }],
        outbounds: [{
          protocol: "vless",
          settings: {
            vnext: [{
              address: host,
              port: parseInt(port),
              users: [{ id, encryption, flow, level: 0 }]
            }]
          },
          streamSettings,
        }]
      };
    } catch (e) {
      throw new Error(`vless parse error: ${e.message}`);
    }
  }

  // -------- trojan:// --------
  if (link.startsWith("trojan://")) {
    try {
      const url = new URL(link);
      const host = url.hostname;
      const port = url.port || 443;
      const password = url.username;
      const params = new URLSearchParams(url.search);
      const sni = params.get("sni") || host;
      const security = params.get("security") || "tls";

      return {
        inbounds: [{ port: socksPort, protocol: "socks", settings: { auth: "noauth", udp: true } }],
        outbounds: [{
          protocol: "trojan",
          settings: { servers: [{ address: host, port: parseInt(port), password, level: 0 }] },
          streamSettings: {
            network: "tcp",
            security,
            tlsSettings: { serverName: sni },
            realitySettings: null,
          }
        }]
      };
    } catch (e) {
      throw new Error(`trojan parse error: ${e.message}`);
    }
  }

  // -------- ss:// (پشتیبانی کامل از فرمت‌های مختلف) --------
  if (link.startsWith("ss://")) {
    try {
      let content = link.substring(5);
      if (content.includes("#")) content = content.split("#")[0];

      let method, password, host, port;
      let decoded = content;

      try {
        const decodedBase64 = Buffer.from(content, "base64").toString("utf-8");
        if (decodedBase64 && decodedBase64.length > 0 && decodedBase64.includes("@")) {
          decoded = decodedBase64;
        }
      } catch (_) {}

      if (decoded.includes("@")) {
        const [methodPass, hostPort] = decoded.split("@");
        
        let methodPassDecoded = methodPass;
        try {
          if (/^[A-Za-z0-9+/]+=*$/.test(methodPass)) {
            const decodedMethodPass = Buffer.from(methodPass, "base64").toString("utf-8");
            if (decodedMethodPass && decodedMethodPass.length > 0) {
              methodPassDecoded = decodedMethodPass;
            }
          }
        } catch (_) {}

        const parts = methodPassDecoded.split(":");
        if (parts.length >= 2) {
          method = parts[0];
          password = parts.slice(1).join(":");
        } else {
          const plainParts = methodPass.split(":");
          if (plainParts.length >= 2) {
            method = plainParts[0];
            password = plainParts.slice(1).join(":");
          } else {
            throw new Error("فرمت ss نامعتبر: unable to extract method and password");
          }
        }

        const hostPortParts = hostPort.split(":");
        if (hostPortParts.length >= 2) {
          host = hostPortParts[0];
          port = hostPortParts[1];
        } else {
          const ipv6Match = hostPort.match(/^\[([^\]]+)\]:(\d+)$/);
          if (ipv6Match) {
            host = ipv6Match[1];
            port = ipv6Match[2];
          } else {
            throw new Error("فرمت ss نامعتبر: unable to extract host and port");
          }
        }
      } else if (decoded.includes("?")) {
        const [hostPort, query] = decoded.split("?");
        const hostPortParts = hostPort.split(":");
        if (hostPortParts.length >= 2) {
          host = hostPortParts[0];
          port = hostPortParts[1];
        } else {
          const ipv6Match = hostPort.match(/^\[([^\]]+)\]:(\d+)$/);
          if (ipv6Match) {
            host = ipv6Match[1];
            port = ipv6Match[2];
          } else {
            throw new Error("فرمت ss نامعتبر: unable to extract host and port");
          }
        }
        const params = new URLSearchParams(query);
        method = params.get("method");
        password = params.get("password");
        if (!method || !password) {
          throw new Error("فرمت ss نامعتبر: missing method or password in query");
        }
      } else {
        const match = decoded.match(/^([^:]+):([^@]+)@([^:]+):(\d+)$/);
        if (match) {
          method = match[1];
          password = match[2];
          host = match[3];
          port = match[4];
        } else {
          try {
            const reDecoded = Buffer.from(decoded, "base64").toString("utf-8");
            if (reDecoded && reDecoded.includes("@")) {
              const [methodPass, hostPort] = reDecoded.split("@");
              const parts = methodPass.split(":");
              if (parts.length >= 2) {
                method = parts[0];
                password = parts.slice(1).join(":");
              }
              const hostPortParts = hostPort.split(":");
              if (hostPortParts.length >= 2) {
                host = hostPortParts[0];
                port = hostPortParts[1];
              } else {
                const ipv6Match = hostPort.match(/^\[([^\]]+)\]:(\d+)$/);
                if (ipv6Match) {
                  host = ipv6Match[1];
                  port = ipv6Match[2];
                } else {
                  throw new Error("فرمت ss نامعتبر: unable to extract host and port");
                }
              }
            } else {
              throw new Error("فرمت ss نامعتبر: unknown format");
            }
          } catch (_) {
            throw new Error("فرمت ss نامعتبر: all parsing attempts failed");
          }
        }
      }

      if (!method || !password || !host || !port) {
        throw new Error("فرمت ss نامعتبر: missing required fields");
      }

      const portNum = parseInt(port);
      if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        throw new Error(`فرمت ss نامعتبر: invalid port ${port}`);
      }

      return {
        inbounds: [{ port: socksPort, protocol: "socks", settings: { auth: "noauth", udp: true } }],
        outbounds: [{
          protocol: "shadowsocks",
          settings: {
            servers: [{
              address: host,
              port: portNum,
              method: method,
              password: password,
              level: 0,
            }]
          }
        }]
      };
    } catch (e) {
      throw new Error(`ss parse error: ${e.message}`);
    }
  }

  throw new Error("پروتکل پشتیبانی نشده");
}

// ============================================================
//  مدیریت پورت‌های تصادفی
// ============================================================

const usedPorts = new Set();

function getRandomPort() {
  let port;
  let attempts = 0;
  do {
    port = Math.floor(Math.random() * (65000 - 10000 + 1)) + 10000;
    attempts++;
    if (attempts > 100) break;
  } while (usedPorts.has(port));
  usedPorts.add(port);
  return port;
}

// ============================================================
//  تست سرعت یک کانفیگ
// ============================================================

async function testSpeed(link, xrayPath, timeoutMs, testUrls) {
  return new Promise((resolve) => {
    const testId = uuidv4().slice(0, 8);
    const socksPort = getRandomPort();

    let downloadSpeed = 0;
    let error = null;
    let isResolved = false;
    let xrayLog = "";

    let xrayConfig;
    try {
      xrayConfig = parseLinkToXrayConfig(link, socksPort);
    } catch (err) {
      logToAll(`❌ Parse error: ${err.message}`, "error");
      usedPorts.delete(socksPort);
      resolve({ link, speed: 0, error: `Parse error: ${err.message}` });
      return;
    }

    const xrayProc = spawn(xrayPath, ["run", "-config", "stdin:"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    xrayProc.stdin.write(JSON.stringify(xrayConfig, null, 2));
    xrayProc.stdin.end();

    xrayProc.stdout.on("data", (data) => {
      const str = data.toString();
      xrayLog += str;
      if (str.includes("Warning") || str.includes("Error") || str.includes("Failed")) {
        logToAll(`[Xray ${testId}] ${str.trim()}`, "warn");
      }
    });
    xrayProc.stderr.on("data", (data) => {
      const str = data.toString();
      xrayLog += str;
      if (str.includes("Warning") || str.includes("Error") || str.includes("Failed")) {
        logToAll(`[Xray ${testId}] ${str.trim()}`, "error");
      }
    });
    xrayProc.on("error", (err) => {
      logToAll(`[Xray ${testId}] process error: ${err.message}`, "error");
      error = err.message;
    });

    const timeoutHandle = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        xrayProc.kill();
        usedPorts.delete(socksPort);
        logToAll(`⏱️ Timeout for ${link.substring(0, 50)}...`, "warn");
        resolve({ link, speed: 0, error: "Timeout", log: xrayLog });
      }
    }, timeoutMs + 5000);

    setTimeout(async () => {
      if (isResolved) return;

      try {
        const proxyAgent = new SocksProxyAgent(`socks5://127.0.0.1:${socksPort}`);
        let success = false;

        for (const testUrl of testUrls) {
          if (success) break;
          try {
            logToAll(`🌐 شروع دانلود از ${testUrl} برای ${link.substring(0, 30)}... (پورت: ${socksPort})`, "info");
            const startTime = Date.now();
            const response = await axios({
              method: "get",
              url: testUrl,
              httpAgent: proxyAgent,
              httpsAgent: proxyAgent,
              timeout: timeoutMs,
              responseType: "stream",
            });

            const totalBytes = parseInt(response.headers["content-length"]) || 10 * 1024 * 1024;
            let downloaded = 0;

            response.data.on("data", (chunk) => {
              downloaded += chunk.length;
            });

            await new Promise((resolveStream) => {
              response.data.on("end", () => {
                const elapsed = (Date.now() - startTime) / 1000;
                downloadSpeed = elapsed > 0 ? (downloaded * 8) / (elapsed * 1024 * 1024) : 0;
                success = true;
                resolveStream();
              });
              response.data.on("error", (err) => {
                error = err.message;
                resolveStream();
              });
            });
            if (success) break;
          } catch (err) {
            error = err.message;
            logToAll(`⚠️ لینک تستی ${testUrl} پاسخ نداد، تلاش با لینک بعدی...`, "warn");
          }
        }

        if (!success && downloadSpeed === 0) {
          error = error || "همه لینک‌های تستی شکست خوردند";
        }
      } catch (err) {
        error = err.message;
        logToAll(`❌ Download error: ${err.message}`, "error");
      } finally {
        clearTimeout(timeoutHandle);
        if (!isResolved) {
          isResolved = true;
          xrayProc.kill();
          usedPorts.delete(socksPort);
          resolve({ link, speed: downloadSpeed, error, log: xrayLog });
        }
      }
    }, 3000);
  });
}

// ============================================================
//  نوشتن نتیجه به فایل
// ============================================================

function appendResult(link, speed) {
  const hashIndex = link.indexOf("#");
  let flag = "";
  if (hashIndex !== -1) {
    const name = link.substring(hashIndex + 1).trim();
    flag = extractFlagFromName(name);
  }
  const cleanLink = link.split("#")[0];
  const speedNum = speed.toFixed(2);
  const finalName = flag ? `${flag} OBSi Shop` : "OBSi Shop";
  const line = `${cleanLink}#${finalName} (${speedNum})\n`;
  fs.appendFileSync(CONFIG.outputFile, line, "utf8");
}

// ============================================================
//  تابع اصلی تست (با پشتیبانی از توقف)
// ============================================================

async function runSpeedTest(manual = false) {
  if (isTestRunning) {
    logToAll("⚠️ تست در حال اجراست، لطفاً صبر کنید.", "warn");
    return;
  }

  isTestRunning = true;
  testStopRequested = false;
  logToAll("🔄 شروع اجرای تست...", "info");

  try {
    const startTime = Date.now();

    const configDownloaded = await downloadConfigs();
    if (!configDownloaded) {
      logToAll("⚠️ دانلود کانفیگ ناموفق، تست ادامه نمی‌یابد.", "error");
      isTestRunning = false;
      return;
    }

    logToAll("🔄 خواندن کانفیگ‌ها از configs.txt...", "info");
    const allLinks = getConfigsFromFile(CONFIG.configsFile);
    logToAll(`✅ تعداد کل کانفیگ‌ها: ${allLinks.length}`, "success");

    if (allLinks.length === 0) {
      logToAll("⚠️ هیچ کانفیگی پیدا نشد.", "warn");
      isTestRunning = false;
      return;
    }

    fs.writeFileSync(CONFIG.outputFile, "", "utf8");

    let acceptedCount = 0;
    const threshold = CONFIG.speedThresholdMbps;

    for (let i = 0; i < allLinks.length; i += CONFIG.concurrency) {
      if (testStopRequested) {
        logToAll("⏹️ تست توسط کاربر متوقف شد.", "warn");
        break;
      }

      const batch = allLinks.slice(i, i + CONFIG.concurrency);
      logToAll(`\n📦 Batch ${Math.floor(i / CONFIG.concurrency) + 1}: تست ${batch.length} کانفیگ...`, "info");

      const batchPromises = batch.map((link) =>
        testSpeed(link, CONFIG.xrayPath, CONFIG.timeoutMs, CONFIG.testFileUrls)
      );
      const batchResults = await Promise.allSettled(batchPromises);

      for (const result of batchResults) {
        if (result.status === "fulfilled") {
          const data = result.value;
          if (data.speed >= threshold) {
            appendResult(data.link, data.speed);
            acceptedCount++;
            logToAll(`✅ قبول (${acceptedCount}): ${data.speed.toFixed(2)} Mbps`, "success");
          } else {
            logToAll(`❌ رد: ${data.speed.toFixed(2)} Mbps (خطا: ${data.error || "ندارد"})`, "error");
          }
        } else {
          logToAll(`❌ خطای غیرمنتظره: ${result.reason}`, "error");
        }
      }
      logToAll(`⏳ پیشرفت: ${Math.min(i + CONFIG.concurrency, allLinks.length)} از ${allLinks.length}`, "info");
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    logToAll(`\n✅ فرآیند کامل شد. تعداد کل کانفیگ‌های قابل قبول: ${acceptedCount} (زمان: ${elapsed} ثانیه)`, "success");
    logToAll(`📄 نتایج در فایل ${CONFIG.outputFile} ذخیره شد.`, "info");
  } catch (error) {
    logToAll(`❌ خطا در تست: ${error.message}`, "error");
  } finally {
    isTestRunning = false;
    testStopRequested = false;
  }
}

// ============================================================
//  راه‌اندازی وب‌سرور
// ============================================================

app.get("/", (req, res) => {
  const lastUpdate = fs.existsSync(CONFIG.outputFile) 
    ? fs.statSync(CONFIG.outputFile).mtime.toLocaleString() 
    : "هنوز اجرا نشده";
  
  const resultCount = fs.existsSync(CONFIG.outputFile)
    ? fs.readFileSync(CONFIG.outputFile, "utf8").split("\n").filter(l => l.trim().length > 0 && l.includes("OBSi Shop")).length
    : 0;

  const configCount = fs.existsSync(CONFIG.configsFile)
    ? fs.readFileSync(CONFIG.configsFile, "utf8").split("\n").filter(l => l.trim().length > 0 && /^(vmess|vless|trojan|ss):\/\//i.test(l)).length
    : 0;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>V2Ray Speed Test Bot</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: #0f0f1a;
          color: #e0e0e0;
          min-height: 100vh;
          display: flex;
          justify-content: center;
          padding: 20px;
        }
        .container {
          max-width: 900px;
          width: 100%;
        }
        .header {
          text-align: center;
          padding: 30px 0 20px;
          border-bottom: 1px solid #2a2a3a;
        }
        .header h1 {
          font-size: 2.2em;
          background: linear-gradient(135deg, #6c5ce7, #00b894);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        .header p {
          color: #8888aa;
          margin-top: 5px;
        }
        .status-bar {
          display: flex;
          flex-wrap: wrap;
          gap: 15px;
          padding: 20px;
          background: #1a1a2e;
          border-radius: 12px;
          margin: 20px 0;
          border: 1px solid #2a2a4a;
        }
        .status-item {
          flex: 1;
          min-width: 120px;
          text-align: center;
        }
        .status-item .label {
          font-size: 12px;
          color: #8888aa;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        .status-item .value {
          font-size: 1.4em;
          font-weight: bold;
          margin-top: 4px;
          color: #6c5ce7;
        }
        .status-item .value.success { color: #00b894; }
        .status-item .value.warning { color: #fdcb6e; }
        .status-item .value.error { color: #e17055; }
        
        .controls {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
          margin: 20px 0;
        }
        .btn {
          padding: 12px 28px;
          border: none;
          border-radius: 8px;
          font-size: 1em;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s;
          flex: 1;
          min-width: 150px;
        }
        .btn-start {
          background: #00b894;
          color: #fff;
        }
        .btn-start:hover { background: #00a381; transform: scale(1.02); }
        .btn-start:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        
        .btn-stop {
          background: #e17055;
          color: #fff;
        }
        .btn-stop:hover { background: #d63031; transform: scale(1.02); }
        .btn-stop:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        
        .btn-refresh {
          background: #2a2a4a;
          color: #e0e0e0;
        }
        .btn-refresh:hover { background: #3a3a5a; transform: scale(1.02); }
        
        .btn-download {
          background: #6c5ce7;
          color: #fff;
        }
        .btn-download:hover { background: #5a4bd1; transform: scale(1.02); }
        
        .log-container {
          background: #0a0a16;
          border-radius: 12px;
          border: 1px solid #1a1a2e;
          padding: 15px;
          margin: 20px 0;
          max-height: 400px;
          overflow-y: auto;
          font-family: 'Courier New', monospace;
          font-size: 13px;
          line-height: 1.6;
        }
        .log-container::-webkit-scrollbar {
          width: 6px;
        }
        .log-container::-webkit-scrollbar-track {
          background: #0a0a16;
        }
        .log-container::-webkit-scrollbar-thumb {
          background: #2a2a4a;
          border-radius: 3px;
        }
        .log-entry {
          padding: 2px 0;
          border-bottom: 1px solid #111122;
        }
        .log-entry .time {
          color: #555577;
          margin-right: 10px;
        }
        .log-entry .type-info { color: #74b9ff; }
        .log-entry .type-success { color: #55efc4; }
        .log-entry .type-error { color: #ff7675; }
        .log-entry .type-warn { color: #fdcb6e; }
        
        .footer {
          text-align: center;
          padding: 20px;
          color: #555577;
          font-size: 13px;
          border-top: 1px solid #1a1a2e;
          margin-top: 20px;
        }
        .cron-info {
          background: #1a1a2e;
          border-radius: 8px;
          padding: 15px 20px;
          margin: 15px 0;
          display: flex;
          flex-wrap: wrap;
          gap: 20px;
          justify-content: space-around;
          border: 1px solid #2a2a4a;
        }
        .cron-info span {
          color: #8888aa;
          font-size: 14px;
        }
        .cron-info strong {
          color: #e0e0e0;
        }
        @media (max-width: 600px) {
          .status-item { min-width: 80px; }
          .btn { min-width: 100px; padding: 10px 16px; font-size: 0.9em; }
          .header h1 { font-size: 1.6em; }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🚀 V2Ray Speed Test</h1>
          <p>ربات تست سرعت کانفیگ‌های V2Ray با مدیریت کامل</p>
        </div>

        <div class="status-bar">
          <div class="status-item">
            <div class="label">وضعیت تست</div>
            <div class="value" id="testStatus">⏸️ متوقف</div>
          </div>
          <div class="status-item">
            <div class="label">کانفیگ‌های تست‌شده</div>
            <div class="value success" id="resultCount">${resultCount}</div>
          </div>
          <div class="status-item">
            <div class="label">کل کانفیگ‌ها</div>
            <div class="value" id="configCount">${configCount}</div>
          </div>
          <div class="status-item">
            <div class="label">آخرین بروزرسانی</div>
            <div class="value" id="lastUpdate" style="font-size:1em;">${lastUpdate}</div>
          </div>
        </div>

        <div class="cron-info">
          <span>🔧 <strong>Cron Job:</strong> هر ۲ ساعت یکبار</span>
          <span>🌐 <strong>منبع کانفیگ:</strong> <a href="${CONFIG.remoteConfigUrl}" target="_blank" style="color:#6c5ce7;">mark.txt</a></span>
          <span>📌 <strong>آستانه سرعت:</strong> ${CONFIG.speedThresholdMbps} Mbps</span>
        </div>

        <div class="controls">
          <button class="btn btn-start" id="btnStart" onclick="startTest()">▶️ شروع تست</button>
          <button class="btn btn-stop" id="btnStop" onclick="stopTest()" disabled>⏹️ توقف تست</button>
          <button class="btn btn-download" onclick="downloadResult()">📥 دانلود result.txt</button>
          <button class="btn btn-refresh" onclick="refreshStatus()">🔄 بروزرسانی</button>
        </div>

        <div class="log-container" id="logContainer">
          <div id="logEntries">
            <div class="log-entry"><span class="time">[${new Date().toLocaleString()}]</span> <span class="type-info">✅ ربات راه‌اندازی شد. منتظر دستورات...</span></div>
          </div>
        </div>

        <div class="footer">
          V2Ray Speed Test Bot | <a href="https://railway-speed-test-production.up.railway.app/result.txt" target="_blank" style="color:#6c5ce7;">مشاهده result.txt</a>
        </div>
      </div>

      <script>
        let eventSource = null;

        function connectSSE() {
          if (eventSource) {
            eventSource.close();
          }
          eventSource = new EventSource('/logs');
          eventSource.onmessage = function(event) {
            try {
              const data = JSON.parse(event.data);
              addLog(data.message, data.type, data.timestamp);
            } catch (e) {}
          };
          eventSource.onerror = function() {
            setTimeout(connectSSE, 3000);
          };
        }

        function addLog(message, type, timestamp) {
          const container = document.getElementById('logEntries');
          const time = timestamp ? new Date(timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
          const typeClass = 'type-' + (type || 'info');
          const entry = document.createElement('div');
          entry.className = 'log-entry';
          // رفع خطای سینتکس با استفاده از string concatenation به جای template literal
          entry.innerHTML = '<span class="time">[' + time + ']</span> <span class="' + typeClass + '">' + message + '</span>';
          container.appendChild(entry);
          const logContainer = document.getElementById('logContainer');
          logContainer.scrollTop = logContainer.scrollHeight;
          while (container.children.length > 200) {
            container.removeChild(container.firstChild);
          }
        }

        function updateStatus(status) {
          const el = document.getElementById('testStatus');
          el.textContent = status;
          el.className = 'value';
          if (status.includes('در حال اجرا')) {
            el.classList.add('warning');
          } else if (status.includes('متوقف')) {
            el.classList.add('error');
          } else {
            el.classList.add('success');
          }
        }

        async function startTest() {
          document.getElementById('btnStart').disabled = true;
          document.getElementById('btnStop').disabled = false;
          updateStatus('🔄 در حال اجرا...');
          try {
            const response = await fetch('/start', { method: 'POST' });
            const data = await response.json();
            if (data.success) {
              addLog('✅ تست با موفقیت شروع شد.', 'success');
            } else {
              addLog('❌ خطا در شروع تست: ' + data.message, 'error');
              updateStatus('⏸️ متوقف');
              document.getElementById('btnStart').disabled = false;
              document.getElementById('btnStop').disabled = true;
            }
          } catch (e) {
            addLog('❌ خطا در ارتباط با سرور: ' + e.message, 'error');
            updateStatus('⏸️ متوقف');
            document.getElementById('btnStart').disabled = false;
            document.getElementById('btnStop').disabled = true;
          }
        }

        async function stopTest() {
          document.getElementById('btnStop').disabled = true;
          try {
            const response = await fetch('/stop', { method: 'POST' });
            const data = await response.json();
            if (data.success) {
              addLog('⏹️ درخواست توقف تست ارسال شد.', 'warn');
              updateStatus('⏹️ در حال توقف...');
            } else {
              addLog('❌ خطا در توقف تست: ' + data.message, 'error');
            }
          } catch (e) {
            addLog('❌ خطا در ارتباط با سرور: ' + e.message, 'error');
          }
          document.getElementById('btnStop').disabled = false;
        }

        async function downloadResult() {
          window.open('/result.txt', '_blank');
        }

        async function refreshStatus() {
          try {
            const response = await fetch('/status');
            const data = await response.json();
            document.getElementById('resultCount').textContent = data.resultCount || 0;
            document.getElementById('configCount').textContent = data.configCount || 0;
            document.getElementById('lastUpdate').textContent = data.lastUpdate || 'نامشخص';
            if (data.isRunning) {
              updateStatus('🔄 در حال اجرا...');
              document.getElementById('btnStart').disabled = true;
              document.getElementById('btnStop').disabled = false;
            } else {
              updateStatus('⏸️ متوقف');
              document.getElementById('btnStart').disabled = false;
              document.getElementById('btnStop').disabled = true;
            }
          } catch (e) {
            addLog('❌ خطا در بروزرسانی وضعیت: ' + e.message, 'error');
          }
        }

        setInterval(refreshStatus, 10000);
        connectSSE();
        refreshStatus();
      </script>
    </body>
    </html>
  `);
});

// -------- استریم لاگ با SSE --------
app.get("/logs", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const recentLogs = logBuffer.slice(-100);
  for (const log of recentLogs) {
    res.write(`data: ${JSON.stringify(log)}\n\n`);
  }

  sseClients.push(res);

  req.on("close", () => {
    sseClients = sseClients.filter(client => client !== res);
  });
});

// -------- وضعیت فعلی --------
app.get("/status", (req, res) => {
  const resultCount = fs.existsSync(CONFIG.outputFile)
    ? fs.readFileSync(CONFIG.outputFile, "utf8").split("\n").filter(l => l.trim().length > 0 && l.includes("OBSi Shop")).length
    : 0;

  const configCount = fs.existsSync(CONFIG.configsFile)
    ? fs.readFileSync(CONFIG.configsFile, "utf8").split("\n").filter(l => l.trim().length > 0 && /^(vmess|vless|trojan|ss):\/\//i.test(l)).length
    : 0;

  const lastUpdate = fs.existsSync(CONFIG.outputFile) 
    ? fs.statSync(CONFIG.outputFile).mtime.toLocaleString() 
    : "هنوز اجرا نشده";

  res.json({
    isRunning: isTestRunning,
    resultCount,
    configCount,
    lastUpdate
  });
});

// -------- شروع تست دستی --------
app.post("/start", async (req, res) => {
  if (isTestRunning) {
    return res.json({ success: false, message: "تست در حال اجراست" });
  }
  setImmediate(() => {
    runSpeedTest(true);
  });
  res.json({ success: true, message: "تست شروع شد" });
});

// -------- توقف تست دستی --------
app.post("/stop", (req, res) => {
  if (!isTestRunning) {
    return res.json({ success: false, message: "تستی در حال اجرا نیست" });
  }
  testStopRequested = true;
  logToAll("⏹️ درخواست توقف تست دریافت شد...", "warn");
  res.json({ success: true, message: "درخواست توقف ارسال شد" });
});

// -------- لینک‌های مستقیم --------
app.get("/result.txt", (req, res) => {
  const filePath = path.join(__dirname, CONFIG.outputFile);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send("فایل result.txt هنوز ایجاد نشده است.");
  }
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.sendFile(filePath);
});

app.get("/configs.txt", (req, res) => {
  const filePath = path.join(__dirname, CONFIG.configsFile);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send("فایل configs.txt پیدا نشد.");
  }
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.sendFile(filePath);
});

// ============================================================
//  مدیریت خطاهای غیرمنتظره
// ============================================================

process.on("uncaughtException", (err) => {
  logToAll(`❌ خطای غیرمنتظره: ${err.message}`, "error");
  console.error(err.stack);
});

process.on("unhandledRejection", (reason) => {
  logToAll(`❌ خطای غیرمنتظره (Promise): ${reason}`, "error");
  console.error(reason);
});

// ============================================================
//  اجرای اصلی
// ============================================================

async function main() {
  logToAll("🚀 راه‌اندازی ربات تست سرعت V2Ray...", "info");
  
  const xrayInstalled = await downloadXrayIfNeeded();
  if (!xrayInstalled) {
    logToAll("❌ Xray-core نصب نشد، برنامه متوقف می‌شود.", "error");
    process.exit(1);
  }

  await downloadConfigs();

  setTimeout(async () => {
    logToAll("🚀 اجرای تست اولیه...", "info");
    await runSpeedTest();
  }, 5000);

  // Cron Job هر ۲ ساعت (طبق تنظیمات شما)
  cron.schedule("0 */2 * * *", async () => {
    if (!isTestRunning) {
      logToAll(`⏰ [${new Date().toISOString()}] اجرای تست زمان‌بندی شده...`, "info");
      await runSpeedTest();
    } else {
      logToAll("⏰ تست زمان‌بندی شده به دلیل در حال اجرا بودن تست، انجام نشد.", "warn");
    }
  });

  app.listen(PORT, () => {
    logToAll(`✅ سرور روی پورت ${PORT} اجرا شد.`, "success");
    logToAll(`📄 لینک: https://railway-speed-test-production.up.railway.app/`, "info");
  });
}

main().catch((err) => {
  logToAll(`❌ خطای کلی: ${err.message}`, "error");
  process.exit(1);
});

module.exports = app;
