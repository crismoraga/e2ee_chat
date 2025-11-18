const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
  const url = process.env.URL || 'http://127.0.0.1:5000/ui/';
  const out = process.env.OUT || 'docs/ui_screenshot.png';

  const browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 });
  console.log('cargando', url);
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });
  console.log('esperando 2s para asegurar render...');
  await page.waitForTimeout(2000);
  console.log('capturando screenshot...');
  await page.screenshot({ path: out, fullPage: true });
  await browser.close();
  console.log('screenshot guardado en', out);
})();
