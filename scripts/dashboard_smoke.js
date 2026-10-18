/* Optional end-to-end check of the dashboard in a real (headless) Chrome, plus README screenshots.
 *   npm i playwright-core            (no browser download: uses your installed Chrome/Chromium)
 *   python -m http.server 8077 --directory dashboard &
 *   CHROME=/usr/bin/google-chrome node scripts/dashboard_smoke.js http://127.0.0.1:8077 screenshots
 */
const { chromium } = require("playwright-core");
const assert = require("assert");
const base = process.argv[2] || "http://127.0.0.1:8077";
const outDir = process.argv[3] || "screenshots";

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const errors = [];
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  let dialogs = 0;
  page.on("dialog", async (d) => { dialogs++; await d.dismiss(); });

  await page.goto(base + "/", { waitUntil: "networkidle" });
  await page.waitForSelector("#alert-table tbody tr");
  const total = await page.locator("#alert-table tbody tr").count();
  const kpiTotal = await page.locator(".kpi.static .n").first().textContent();
  assert.strictEqual(String(total), kpiTotal.trim(), "table rows equal KPI total");
  assert(await page.locator("#banner").textContent().then((t) => /SYNTHETIC/.test(t)), "synthetic banner");
  assert((await page.locator("#top-ips li").count()) >= 5, "top IPs rendered");
  assert((await page.locator("#mitre-table tbody tr").count()) >= 8, "MITRE rows rendered");
  assert((await page.locator("#incidents li").count()) >= 5, "incidents rendered");
  const canvasPixels = await page.evaluate(() => {
    const c = document.getElementById("timeline"); const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
    let n = 0; for (let i = 3; i < d.length; i += 4) if (d[i] !== 0) n++; return n;
  });
  assert(canvasPixels > 1000, "timeline canvas has drawn content");
  await page.screenshot({ path: outDir + "/01-dashboard.png" });
  await page.screenshot({ path: outDir + "/01-dashboard-full.png", fullPage: true });

  // severity filter
  await page.click('.kpi[data-sev="critical"]');
  const crit = await page.locator("#alert-table tbody tr").count();
  const critKpi = await page.locator('.kpi[data-sev="critical"] .n').textContent();
  assert.strictEqual(String(crit), critKpi.trim(), "critical filter count");
  await page.click('.kpi[data-sev="critical"]'); // toggle off

  // IP filter + search
  await page.click('.ip-row[data-ip="198.51.100.77"]');
  assert(await page.locator("#alert-table tbody tr").count() >= 3, "IP filter shows several alerts");
  await page.click("#f-reset");
  await page.fill("#f-search", "sysupdate");
  assert((await page.locator("#alert-table tbody tr").count()) >= 2, "search finds sysupdate alerts");
  await page.click("#f-reset");

  // technique filter
  await page.click('#mitre-table tr[data-tech="T1190"]');
  const t1190 = await page.locator("#alert-table tbody tr").count();
  assert(t1190 >= 3 && t1190 < total, "technique filter narrows");
  await page.click("#f-reset");

  // drill-down on the SQLi alert (payload text must be inert)
  await page.fill("#f-search", "SQL injection");
  await page.locator("#alert-table tbody tr").first().click();
  await page.waitForSelector("#drawer:not([hidden])");
  assert(/sqlmap|UNION|SELECT|%27/i.test(await page.locator("pre.evidence").textContent()), "evidence shows payload as text");
  await page.waitForTimeout(500); // let the slide-in animation finish
  await page.screenshot({ path: outDir + "/02-alert-drilldown.png" });
  await page.keyboard.press("Escape");
  assert(await page.locator("#drawer").isHidden(), "Escape closes drawer");
  await page.click("#f-reset");

  // timeline click filters to an hour
  await page.evaluate(() => window.scrollTo(0, 0));
  const box = await page.locator("#timeline").boundingBox();
  await page.mouse.move(box.x + box.width * 0.5, box.y + box.height * 0.6);
  await page.screenshot({ path: outDir + "/03-timeline-hover.png", clip: { x: Math.max(0, box.x - 20), y: Math.max(0, box.y - 60), width: box.width + 40, height: box.height + 90 } });
  assert.strictEqual(dialogs, 0, "no dialogs (XSS payloads inert)");

  // loading a user-supplied report (not labelled synthetic) swaps the banner; a broken file shows an error
  const fs = require("fs"), os = require("os"), path = require("path");
  const custom = JSON.parse(fs.readFileSync("dashboard/data/alerts.json", "utf8"));
  custom.meta.synthetic = false; custom.alerts = custom.alerts.slice(0, 5);
  custom.alerts[0].title = "<img src=x onerror=alert(1)> injected title";
  const tmp = path.join(os.tmpdir(), "custom-alerts.json");
  fs.writeFileSync(tmp, JSON.stringify(custom));
  await page.setInputFiles("#file-input", tmp);
  await page.waitForFunction(() => document.querySelectorAll("#alert-table tbody tr").length === 5);
  assert(/YOUR DATA/.test(await page.locator("#banner").textContent()), "banner switches for user data");
  assert.strictEqual(await page.locator("#alert-table img").count(), 0, "HTML in titles stays text");
  fs.writeFileSync(tmp, "{not json");
  await page.setInputFiles("#file-input", tmp);
  await page.waitForSelector("#error:not([hidden])");
  assert.strictEqual(dialogs, 0, "no dialogs after hostile title");

  // mobile
  const m = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  m.on("pageerror", (e) => errors.push("mobile: " + e));
  await m.goto(base + "/", { waitUntil: "networkidle" });
  await m.waitForSelector("#alert-table tbody tr");
  const sw = await m.evaluate(() => document.documentElement.scrollWidth);
  assert(sw <= 392, "no horizontal overflow on mobile, got " + sw);
  await m.screenshot({ path: outDir + "/04-mobile.png" });

  assert.deepStrictEqual(errors, [], "no console errors: " + errors.join("; "));
  console.log("dashboard smoke test OK:", { alerts: total, critical: crit, mitreTechniqueFilter: t1190 });
  await browser.close();
})().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
