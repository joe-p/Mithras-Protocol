import fs from 'node:fs';
import path from 'node:path';

const projectRoot = path.resolve(new URL('.', import.meta.url).pathname, '..');
const repoRoot = path.resolve(projectRoot, '..', '..');

// const circuitsDir = path.join(
//   repoRoot,
//   'packages',
//   'mithras-contracts-and-circuits',
//   'circuits'
// );

const circuitsDir = path.join(
  repoRoot,
  'mithras-mobile',
  'test-vectors',
  'circom'
);

const assetsDir = path.join(projectRoot, 'assets', 'keys');

const filesToSync = [
  'deposit.zkey',
  'spend.zkey',
];

if (!fs.existsSync(circuitsDir)) {
  console.error(`Circuits directory not found: ${circuitsDir}`);
  process.exit(1);
}

fs.mkdirSync(assetsDir, { recursive: true });

let copied = 0;
let skipped = 0;

for (const fileName of filesToSync) {
  const src = path.join(circuitsDir, fileName);
  const dest = path.join(assetsDir, fileName);

  if (!fs.existsSync(src)) {
    console.error(`Missing required circuit artifact: ${src}`);
    process.exit(1);
  }

  const shouldCopy = (() => {
    if (!fs.existsSync(dest)) return true;
    const srcStat = fs.statSync(src);
    const destStat = fs.statSync(dest);
    return srcStat.mtimeMs > destStat.mtimeMs || srcStat.size !== destStat.size;
  })();

  if (shouldCopy) {
    fs.copyFileSync(src, dest);
    copied += 1;
  } else {
    skipped += 1;
  }
}

console.log(
  `Synced Circom zkeys into assets/keys (copied=${copied}, skipped=${skipped})`
);
