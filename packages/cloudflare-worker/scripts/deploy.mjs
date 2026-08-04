#!/usr/bin/env node
// Deploys with the current git commit and a fresh build timestamp baked into
// the bundle (see src/build-info.ts) so GET /version always reflects exactly
// what was uploaded - not what wrangler.jsonc happens to say, and not
// whatever was true the last time someone remembered to update a constant.
import { execFileSync } from 'node:child_process';

const gitCommit = execFileSync('git', ['rev-parse', '--short=8', 'HEAD']).toString().trim();
const dirty = execFileSync('git', ['status', '--porcelain']).toString().trim().length > 0;
if (dirty) {
  console.warn(`Warning: deploying with uncommitted changes present - git_commit=${gitCommit} will not fully describe what's live.`);
}
const buildTime = new Date().toISOString();

const args = [
  'wrangler', 'deploy',
  '--define', `__GIT_COMMIT__:"${dirty ? gitCommit + '-dirty' : gitCommit}"`,
  '--define', `__BUILD_TIME__:"${buildTime}"`,
  ...process.argv.slice(2),
];

console.log(`Deploying git_commit=${gitCommit}${dirty ? ' (dirty)' : ''} build_time=${buildTime}`);
execFileSync('npx', args, { stdio: 'inherit' });
