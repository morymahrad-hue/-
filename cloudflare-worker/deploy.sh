#!/usr/bin/env bash
set -euo pipefail

echo "=== EdgePanel Automated Cloudflare Workers Installer ==="

if ! command -v npx >/dev/null 2>&1; then
  echo "Error: Node.js / npx is required."
  exit 1
fi

npm install

echo "1) Authenticating with Cloudflare (browser window will open if not logged in)..."
npx wrangler whoami >/dev/null 2>&1 || npx wrangler login

DB_NAME="edgepanel-db"
echo "2) Provisioning D1 Database ($DB_NAME)..."
DB_OUTPUT=$(npx wrangler d1 create "$DB_NAME" 2>&1 || true)
DB_ID=$(echo "$DB_OUTPUT" | grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -n1 || true)

if [ -z "$DB_ID" ]; then
  DB_LIST=$(npx wrangler d1 list --json 2>/dev/null || echo "[]")
  DB_ID=$(node -e "const d=JSON.parse(process.argv[1]); const f=d.find(x=>x.name==='$DB_NAME'); console.log(f?f.uuid:'')" "$DB_LIST")
fi

if [ -n "$DB_ID" ]; then
  echo "   Using D1 database_id: $DB_ID"
  node -e "
    const fs=require('fs');
    let t=fs.readFileSync('wrangler.toml','utf8');
    t=t.replace(/# \[\[d1_databases\]\]\n# binding = \"DB\"\n# database_name = \"edgepanel-db\"\n# database_id = \"[^\"]+\"/,
      '[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = \"edgepanel-db\"\ndatabase_id = \"$DB_ID\"');
    t=t.replace(/database_id = \"[0-9a-f-]+\"/, 'database_id = \"$DB_ID\"');
    fs.writeFileSync('wrangler.toml', t);
  "
else
  echo "   Warning: Could not auto-detect D1 ID. Update wrangler.toml manually if needed."
fi

echo "3) Configuring Admin Credentials & Session Secret..."
read -rp "Admin Username [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -rsp "Admin Password (leave blank to auto-generate): " ADMIN_PASS
echo ""
if [ -z "$ADMIN_PASS" ]; then
  ADMIN_PASS=$(node -e "console.log(require('crypto').randomBytes(12).toString('base64url'))")
  echo "   Generated Admin Password: $ADMIN_PASS"
fi
SESSION_SEC=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

printf "%s" "$ADMIN_USER" | npx wrangler secret put ADMIN_USERNAME
printf "%s" "$ADMIN_PASS" | npx wrangler secret put ADMIN_PASSWORD
printf "%s" "$SESSION_SEC" | npx wrangler secret put SESSION_SECRET

echo "4) Deploying EdgePanel to Cloudflare Workers..."
DEPLOY_OUT=$(npx wrangler deploy 2>&1)
echo "$DEPLOY_OUT"

WORKER_URL=$(echo "$DEPLOY_OUT" | grep -Eo 'https://[a-zA-Z0-9.-]+\.workers\.dev' | head -n1 || true)
echo ""
echo "=== Deployment Complete ==="
echo "Panel URL : ${WORKER_URL:-Check Wrangler output above}"
echo "Username  : $ADMIN_USER"
echo "Password  : $ADMIN_PASS"
