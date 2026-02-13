import { build } from 'esbuild';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const srcEntry = path.join(__dirname, 'src', 'main.jsx');
const distDir = path.join(__dirname, 'dist');
const outJS = path.join(distDir, 'app.js');
const outCSS = path.join(distDir, 'app.css');
const templatePath = path.join(__dirname, 'template.html');
const outHTML = path.join(__dirname, 'index.html');

await fs.mkdir(distDir, { recursive: true });

await build({
  entryPoints: [srcEntry],
  outfile: outJS,
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['es2018'],
  minify: true,
  legalComments: 'none',
  jsx: 'automatic'
});

const [jsCode, template] = await Promise.all([
  fs.readFile(outJS, 'utf8'),
  fs.readFile(templatePath, 'utf8'),
]);

let cssCode = '';
try {
  cssCode = await fs.readFile(outCSS, 'utf8');
} catch {
  cssCode = '';
}

const cssToken = '__APP_CSS__';
const jsToken = '__APP_JS__';
if (!template.includes(cssToken) || !template.includes(jsToken)) {
  throw new Error('template placeholders are missing');
}

// Use function replacements to keep `$` bytes in bundle untouched.
const html = template
  .replace(cssToken, () => cssCode)
  .replace(jsToken, () => jsCode)
  .trim() + '\n';

await fs.writeFile(outHTML, html, 'utf8');
console.log(`WebUI built: ${outHTML}`);
