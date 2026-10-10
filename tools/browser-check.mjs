/* Headless browser harness over the Chrome DevTools Protocol.
   - collects console errors and failed requests
   - evaluates expressions to verify interactions
   - writes screenshots
   Usage: node tools/browser-check.mjs <url> <scenario-file.json> [outDir]
   The scenario file is a JSON array of steps:
     {"eval": "<expression>"} | {"click": "<selector>"} | {"type": ["<selector>","<text>"]}
     | {"wait": 400} | {"shot": "<name>.png"} | {"check": ["<label>", "<expression>"]} */

import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const CHROME = process.env.CHROME_PATH || "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const url = process.argv[2] || "http://127.0.0.1:8000/";
const scenarioPath = process.argv[3];
const outDir = resolve(process.argv[4] || "shots");
mkdirSync(outDir, { recursive: true });

const steps = scenarioPath ? JSON.parse(readFileSync(scenarioPath, "utf8")) : [];
const profile = mkdtempSync(join(tmpdir(), "soc-atlas-chrome-"));
const port = 9333;
const errors = [];
const warnings = [];
const checks = [];

const chrome = spawn(
  CHROME,
  [
    "--headless=new",
    "--disable-gpu",
    "--hide-scrollbars",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${profile}`,
    "--window-size=1440,1200",
    "about:blank",
  ],
  { stdio: "ignore" },
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function targetWs() {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      const list = await response.json();
      const page = list.find((item) => item.type === "page");
      if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
    } catch {
      /* chrome is still starting */
    }
    await sleep(250);
  }
  throw new Error("Chrome DevTools endpoint unavailable");
}

let nextId = 1;
function rpc(ws, method, params = {}) {
  const id = nextId++;
  return new Promise((res, rej) => {
    const onMessage = (event) => {
      let message;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      if (message.id !== id) return;
      ws.removeEventListener("message", onMessage);
      if (message.error) rej(new Error(`${method}: ${message.error.message}`));
      else res(message.result);
    };
    ws.addEventListener("message", onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

const MESSAGE_KIND = {
  error: (text) => errors.push(text),
  warning: (text) => warnings.push(text),
};

async function main() {
  const wsUrl = await targetWs();
  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res, { once: true });
    ws.addEventListener("error", rej, { once: true });
  });

  await rpc(ws, "Runtime.enable");
  await rpc(ws, "Log.enable");
  await rpc(ws, "Page.enable");
  await rpc(ws, "Network.enable");

  ws.addEventListener("message", (event) => {
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.method === "Runtime.exceptionThrown") {
      const details = message.params.exceptionDetails;
      errors.push(`${details.text} ${details.exception?.description || ""}`.trim());
    }
    if (message.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(message.params.type)) {
      const text = message.params.args.map((arg) => arg.value ?? arg.description ?? "").join(" ");
      (MESSAGE_KIND[message.params.type] || errors.push)(text);
    }
    if (message.method === "Log.entryAdded") {
      const entry = message.params.entry;
      if (entry.level === "error") errors.push(`${entry.source}: ${entry.text}`);
      if (entry.level === "warning") warnings.push(`${entry.source}: ${entry.text}`);
    }
    if (message.method === "Network.loadingFailed") {
      const { errorText, type, canceled } = message.params;
      // Aborted image loads happen when a cached <img> src is cleared on purpose.
      if (!canceled && !(type === "Image" && errorText === "net::ERR_ABORTED")) {
        errors.push(`loadingFailed: ${errorText} ${type}`);
      }
    }
  });

  await rpc(ws, "Page.navigate", { url });
  await sleep(2200);

  for (const step of steps) {
    try {
      if (step.wait) await sleep(step.wait);
      if (step.eval) {
        const result = await rpc(ws, "Runtime.evaluate", {
          expression: step.eval,
          awaitPromise: true,
          returnByValue: true,
        });
        if (result.exceptionDetails) errors.push(`eval failed: ${result.exceptionDetails.text}`);
        else if (step.log) console.log(`${step.log}: ${JSON.stringify(result.result.value)}`);
      }
      if (step.click) {
        await rpc(ws, "Runtime.evaluate", {
          expression: `(() => { const el = document.querySelector(${JSON.stringify(step.click)}); if (!el) return false; el.click(); return true; })()`,
          returnByValue: true,
        });
      }
      if (step.type) {
        const [selector, text] = step.type;
        await rpc(ws, "Runtime.evaluate", {
          expression: `(() => {
            const el = document.querySelector(${JSON.stringify(selector)});
            if (!el) return false;
            el.focus();
            el.value = ${JSON.stringify(text)};
            el.dispatchEvent(new Event('input', { bubbles: true }));
            return true;
          })()`,
          returnByValue: true,
        });
      }
      if (step.check) {
        const [label, expression] = step.check;
        const result = await rpc(ws, "Runtime.evaluate", { expression, returnByValue: true });
        const value = result.result?.value;
        const ok = value === true || (typeof value === "number" && value > 0) || (Array.isArray(value) && value.length >= 0 && value !== false);
        checks.push([label, value]);
        if (!value) errors.push(`check failed: ${label} => ${JSON.stringify(value)}`);
      }
      if (step.viewport) {
        const [width, height] = step.viewport;
        await rpc(ws, "Emulation.setDeviceMetricsOverride", {
          width,
          height,
          deviceScaleFactor: 1,
          mobile: Boolean(step.mobile),
        });
      }
      if (step.shot) {
        const full = Boolean(step.full);
        let clip;
        if (full) {
          const metrics = await rpc(ws, "Page.getLayoutMetrics");
          const size = metrics.cssContentSize || metrics.contentSize;
          clip = { x: 0, y: 0, width: Math.min(size.width, 1600), height: Math.min(size.height, 4000), scale: 1 };
        }
        const shot = await rpc(ws, "Page.captureScreenshot", {
          format: "png",
          captureBeyondViewport: full,
          ...(clip ? { clip } : {}),
        });
        writeFileSync(join(outDir, step.shot), Buffer.from(shot.data, "base64"));
        console.log(`shot ${step.shot}`);
      }
    } catch (error) {
      errors.push(`step failed (${JSON.stringify(step).slice(0, 90)}): ${error.message}`);
    }
  }

  for (const [label, value] of checks) console.log(`check ${label}: ${JSON.stringify(value)}`);
  for (const warning of warnings) console.log(`warn ${warning}`);
  for (const error of errors) console.log(`FAIL ${error}`);

  const info = await rpc(ws, "Runtime.evaluate", {
    expression: `JSON.stringify({ title: document.title, attacks: document.querySelectorAll('[data-scenario]').length, detail: !!document.querySelector('#attack-detail .detail__head'), docs: document.querySelectorAll('#readme-nav [data-readme]').length, tray: document.querySelectorAll('#tray-list .tray__chip').length })`,
    returnByValue: true,
  });
  console.log(`page: ${info.result.value}`);

  ws.close();
  chrome.kill();
  try {
    rmSync(profile, { recursive: true, force: true, maxRetries: 3, retryDelay: 120 });
  } catch {
    /* the browser profile may still be locked on Windows; it lives in the temp dir */
  }
  console.log(errors.length ? `${errors.length} error(s)` : "browser check clean");
  process.exit(errors.length ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  chrome.kill();
  process.exit(1);
});
