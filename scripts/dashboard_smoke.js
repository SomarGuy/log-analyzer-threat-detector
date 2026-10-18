/* End-to-end check of the dashboard in a real (headless) Chrome, plus the README screenshots.
 *   npm i playwright-core            (no browser download: uses your installed Chrome/Chromium)
 *   python -m http.server 8000 --directory dashboard &
 *   CHROME=/usr/bin/google-chrome node scripts/dashboard_smoke.js http://127.0.0.1:8000 screenshots
 */
const { chromium } = require("playwright-core");
const assert = require("assert");
const fs = require("fs"), os = require("os"), path = require("path");
const base = process.argv[2] || "http://127.0.0.1:8000";
const outDir = process.argv[3] || "screenshots";

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const errors = [];
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, permissions: ["clipboard-read", "clipboard-write"] });
  const page = await ctx.newPage();
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  let dialogs = 0;
  page.on("dialog", async (d) => { dialogs++; await d.dismiss(); });
  const rows = () => page.locator("#alert-table tbody tr").count();

  await page.goto(base + "/", { waitUntil: "networkidle" });
  await page.waitForSelector("#alert-table tbody tr");
  const total = await rows();
  const kpiTotal = await page.locator(".kpi.static .n").first().textContent();
  assert.strictEqual(String(total), kpiTotal.trim(), "table rows equal the total alerts stat");
  assert(/SYNTHETIC/.test(await page.locator("#banner").textContent()), "synthetic banner");
  assert(/log-analyzer/.test(await page.locator("#statusbar").textContent()), "status bar present");
  assert((await page.locator("#top-ips li").count()) >= 5, "top IPs rendered");
  assert((await page.locator("#mitre-table tbody tr").count()) >= 8, "MITRE rows rendered");
  assert((await page.locator("#incidents li").count()) >= 5, "incidents rendered");
  assert(await page.evaluate(() => getComputedStyle(document.body).backgroundColor) === "rgb(6, 9, 6)", "dark console background");
  assert(await page.evaluate(() => document.fonts.check("13px Tailmono")), "bundled monospace font loads");
  const canvasPixels = await page.evaluate(() => {
    const c = document.getElementById("timeline"); const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
    let n = 0; for (let i = 3; i < d.length; i += 4) if (d[i] !== 0) n++; return n;
  });
  assert(canvasPixels > 1000, "timeline canvas has drawn content");

  // event tail: keeps scrolling by itself, and p pauses it
  assert((await page.locator("#tail .tl-line").count()) >= 10, "tail has lines");
  const t0 = await page.locator("#tail-state").textContent();
  await page.waitForFunction((was) => document.getElementById("tail-state").textContent !== was, t0, { timeout: 8000 });
  await page.keyboard.press("p");
  assert(/paused/.test(await page.locator("#tail-state").textContent()), "p pauses the tail");
  const frozen = await page.locator("#tail-state").textContent();
  await page.waitForTimeout(1600);
  assert.strictEqual(await page.locator("#tail-state").textContent(), frozen, "paused tail does not move");
  await page.keyboard.press("p");
  assert(/replay/.test(await page.locator("#tail-state").textContent()), "p resumes the tail");
  await page.mouse.move(5, 5);
  await page.screenshot({ path: outDir + "/01-dashboard.png" });
  await page.setViewportSize({ width: 1440, height: 1800 });
  await page.waitForTimeout(400);
  await page.screenshot({ path: outDir + "/01-dashboard-full.png" });
  await page.setViewportSize({ width: 1440, height: 900 });

  // keyboard: j / k move the highlighted alert, Enter opens it, j/k inside the drawer flips alerts
  const curId = () => page.locator("#alert-table tbody tr.cur").getAttribute("data-id");
  const first = await curId();
  await page.keyboard.press("j");
  const second = await curId();
  assert.notStrictEqual(first, second, "j moves down");
  await page.keyboard.press("k");
  assert.strictEqual(await curId(), first, "k moves back up");
  await page.keyboard.press("G");
  assert.notStrictEqual(await curId(), first, "G jumps to the last alert");
  await page.keyboard.press("g");
  assert.strictEqual(await curId(), first, "g jumps to the first alert");
  await page.keyboard.press("Enter");
  await page.waitForSelector("#drawer:not([hidden])");
  const title1 = await page.locator("#drawer-title").textContent();
  await page.keyboard.press("j");
  assert.notStrictEqual(await page.locator("#drawer-title").textContent(), title1, "j inside the drawer opens the next alert");
  await page.keyboard.press("Escape");
  assert(await page.locator("#drawer").isHidden(), "Escape closes the drawer");

  // ? help, / filter, number keys, r reset
  await page.keyboard.press("?");
  assert(await page.locator("#help").isVisible(), "? opens help");
  await page.screenshot({ path: outDir + "/06-keyboard-help.png" });
  await page.keyboard.press("Escape");
  assert(await page.locator("#help").isHidden(), "Esc closes help");
  await page.keyboard.press("/");
  assert.strictEqual(await page.evaluate(() => document.activeElement.id), "f-search", "/ focuses the filter box");
  await page.keyboard.type("sysupdate");
  assert((await rows()) >= 2 && (await rows()) < total, "typing filters the list");
  await page.keyboard.press("Escape");
  assert.notStrictEqual(await page.evaluate(() => document.activeElement.id), "f-search", "Esc leaves the filter box");
  await page.keyboard.press("r");
  assert.strictEqual(await rows(), total, "r resets the filters");
  await page.keyboard.press("1");
  const critKpi = await page.locator('.meter[data-sev="critical"] .n').textContent();
  assert.strictEqual(String(await rows()), critKpi.trim(), "1 filters to critical");
  await page.keyboard.press("1");
  assert.strictEqual(await rows(), total, "1 again clears it");

  // severity meter filter, IP filter, technique filter
  await page.click('.meter[data-sev="critical"]');
  const crit = await rows();
  assert.strictEqual(String(crit), critKpi.trim(), "critical filter count");
  await page.click('.meter[data-sev="critical"]');
  await page.click('.ip-row[data-ip="198.51.100.77"]');
  assert((await rows()) >= 3, "IP filter shows several alerts");
  await page.click("#f-reset");
  await page.click('#mitre-table tr[data-tech="T1190"]');
  const t1190 = await rows();
  assert(t1190 >= 3 && t1190 < total, "technique filter narrows");
  await page.click("#f-reset");
  await page.click('.inc[data-inc="INC-02"]');
  assert((await rows()) >= 5, "incident filter shows its alerts");
  await page.click("#f-reset");

  // CSV export honours the filter
  await page.fill("#f-search", "SQL injection");
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#f-export")]);
  const csv = fs.readFileSync(await dl.path(), "utf8").trim().split("\n");
  assert.strictEqual(csv.length, (await rows()) + 1, "CSV has header plus the filtered rows");
  assert(/^"id","severity"/.test(csv[0]), "CSV header");

  // drill-down on the SQLi alert (payload text must be inert), copy as ticket note
  await page.locator("#alert-table tbody tr").first().click();
  await page.waitForSelector("#drawer:not([hidden])");
  assert(/sqlmap|UNION|SELECT|%27/i.test(await page.locator("pre.evidence").textContent()), "evidence shows payload as text");
  await page.click("#d-copy");
  await page.waitForFunction(() => /Copied/.test(document.querySelector(".toast").textContent));
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  assert(/^\[CRITICAL\] ALR-\d+: /.test(clip) && /Recommended response:/.test(clip), "ticket note copied");
  await page.evaluate(() => { document.getElementById("drawer-body").scrollTop = 0; });
  await page.waitForTimeout(400);
  await page.screenshot({ path: outDir + "/02-alert-drilldown.png" });
  await page.keyboard.press("Escape");
  await page.click("#f-reset");

  // timeline hover
  await page.evaluate(() => window.scrollTo(0, 0));
  const box = await page.locator("#timeline").boundingBox();
  await page.mouse.move(box.x + box.width * 0.5, box.y + box.height * 0.6);
  await page.screenshot({ path: outDir + "/03-timeline-hover.png", clip: { x: Math.max(0, box.x - 20), y: Math.max(0, box.y - 40), width: box.width + 40, height: box.height + 70 } });
  // timeline click filters to an hour
  const nBefore = await rows();
  await page.mouse.click(box.x + box.width * 0.5, box.y + box.height * 0.6);
  assert((await rows()) < nBefore, "timeline click narrows to that hour");
  await page.click("#f-reset");
  assert.strictEqual(dialogs, 0, "no dialogs (XSS payloads inert)");

  // loading a user-supplied report (not labelled synthetic) swaps the banner; a broken file shows an error
  const custom = JSON.parse(fs.readFileSync("dashboard/data/alerts.json", "utf8"));
  custom.meta.synthetic = false; custom.alerts = custom.alerts.slice(0, 5);
  custom.alerts[0].title = "<img src=x onerror=alert(1)> injected title";
  custom.alerts[0].timeline[0].event = "<script>alert(2)</script> tail line";
  const tmp = path.join(os.tmpdir(), "custom-alerts-" + process.pid + ".json");
  fs.writeFileSync(tmp, JSON.stringify(custom));
  await page.setInputFiles("#file-input", tmp);
  await page.waitForFunction(() => document.querySelectorAll("#alert-table tbody tr").length === 5);
  assert(/YOUR DATA/.test(await page.locator("#banner").textContent()), "banner switches for user data");
  assert.strictEqual(await page.locator("#alert-table img").count(), 0, "HTML in titles stays text");
  assert.strictEqual(await page.locator("#tail script, #tail img").count(), 0, "HTML in tail lines stays text");
  fs.writeFileSync(tmp, "{not json");
  await page.setInputFiles("#file-input", tmp);
  await page.waitForSelector("#error:not([hidden])");
  fs.unlinkSync(tmp);
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
