import fs from 'node:fs';
import path from 'node:path';

const projectRoot = path.resolve(new URL('.', import.meta.url).pathname, '..');
const resDir = path.join(projectRoot, 'android', 'app', 'src', 'main', 'res');

if (!fs.existsSync(resDir)) {
  console.error(`Android res directory not found: ${resDir}`);
  process.exit(1);
}

const entries = fs.readdirSync(resDir, { withFileTypes: true });
const mipmapDirs = entries
  .filter((dirent) => dirent.isDirectory() && /^mipmap-.*dpi$/.test(dirent.name))
  .map((dirent) => path.join(resDir, dirent.name));

let copied = 0;
for (const dir of mipmapDirs) {
  const src = path.join(dir, 'ic_launcher.png');
  const dest = path.join(dir, 'ic_launcher_round.png');

  if (!fs.existsSync(src)) continue;

  fs.copyFileSync(src, dest);
  copied += 1;
}

console.log(`Synced ic_launcher_round.png in ${copied} mipmap folders`);
