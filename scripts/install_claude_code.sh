#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$REPO_DIR/.mcp.json"

export REPO_DIR

node <<'NODE'
const fs = require('fs');
const path = require('path');

const repoDir = process.env.REPO_DIR;
const target = path.join(repoDir, '.mcp.json');

let doc = { mcpServers: {} };
if (fs.existsSync(target)) {
  const raw = fs.readFileSync(target, 'utf8');
  doc = raw.trim() ? JSON.parse(raw) : { mcpServers: {} };
}

if (!doc.mcpServers || typeof doc.mcpServers !== 'object') {
  doc.mcpServers = {};
}

doc.mcpServers['webrtc-terminal'] = {
  command: 'node',
  args: [path.join(repoDir, 'src/index.js')],
};

fs.writeFileSync(target, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`Updated ${target}`);
NODE

echo "Claude Code MCP entry installed in $TARGET"
