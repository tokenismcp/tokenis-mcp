#!/usr/bin/env bash
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Packs @tokenis/crypto exactly as `npm publish` would, installs the tarball
# into a throwaway project, and checks that it type-checks under NodeNext and
# runs from both ESM and CommonJS. Guards against a tarball that is missing
# its WebAssembly or license files.
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tarball="$(npm pack --silent --pack-destination "$work" | tail -n 1)"
listing="$(tar tzf "$work/$tarball")"
for required in package/wasm/tokenis_wasm.js package/wasm/tokenis_wasm_bg.wasm \
  package/wasm/tokenis_wasm.d.ts package/dist/index.js package/dist/index.d.ts \
  package/LICENSE package/THIRD-PARTY-NOTICES.md; do
  grep -qx "$required" <<<"$listing" || { echo "missing from tarball: $required"; exit 1; }
done

cd "$work"
npm init -y >/dev/null
npm pkg set type=module >/dev/null
npm install --silent --no-audit --no-fund "./$tarball" typescript@5 @types/node@24 >/dev/null
cat > consumer.ts <<'TS'
import { Decryptor, Owner, encrypt, evaluateAffineMasked, keygen } from "@tokenis/crypto";
const { privateKey, publicKey } = keygen();
const total = encrypt(publicKey, 1200n).add(encrypt(publicKey, 34n)).mul(2n);
if (new Decryptor(privateKey).decrypt(total) !== 2468n) throw new Error("decrypt");
const owner = new Owner();
const f = { coefficients: [3n, -2n], intercept: 5n };
const { masked, correction } = owner.delegateAffine(f, [100n, 7n]);
if (owner.unblindAffine(evaluateAffineMasked(f, masked), correction) !== 291n) throw new Error("affine");
console.log("esm ok");
TS
cat > tsconfig.json <<'JSON'
{ "compilerOptions": { "module": "NodeNext", "moduleResolution": "NodeNext", "target": "ES2022",
  "strict": true, "skipLibCheck": false, "outDir": "out" }, "files": ["consumer.ts"] }
JSON
npx tsc -p tsconfig.json
node out/consumer.js
node -e 'const t = require("@tokenis/crypto"); const k = t.keygen(); if (new t.Decryptor(k.privateKey).decrypt(t.encrypt(k.publicKey, -5n)) !== -5n) process.exit(1); console.log("cjs ok")'
echo "package ok: $tarball"
