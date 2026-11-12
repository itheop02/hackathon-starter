const { spawnSync } = require('node:child_process');
const path = require('node:path');
const binary = process.env.PYTHON_BINARY || (process.platform === 'win32' ? 'python' : 'python3');
const result = spawnSync(binary, [path.join(__dirname, 'test.py')], { stdio: 'inherit', windowsHide: true, env: { ...process.env, NODE_BINARY: process.execPath } });
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);
