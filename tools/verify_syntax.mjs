import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readdirSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const jsDir = join(__dirname, '../app/www/js');

try {
  const files = readdirSync(jsDir).filter(f => f.endsWith('.js'));
  let failed = false;
  let checked = 0;

  for (const file of files) {
    try {
      execSync(`node --check "${join(jsDir, file)}"`, { stdio: 'pipe' });
      checked++;
    } catch (e) {
      console.error(`FAIL — Syntax error in ${file}:`);
      console.error(e.stderr.toString());
      failed = true;
    }
  }

  if (failed) {
    process.exit(1);
  }
  console.log(`PASS — ${checked} JS files passed syntax check`);
} catch (e) {
  console.error('FAIL — Could not run syntax checks:', e.message);
  process.exit(1);
}
