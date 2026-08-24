import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const nextDir = join(root, ".next");

function walk(dir, acc = []) {
  if (!existsSync(dir)) return acc;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, acc);
    else acc.push(full);
  }
  return acc;
}

if (!existsSync(nextDir)) {
  console.error("assert-share-route: .next is missing; run pnpm build first");
  process.exit(1);
}

const shareFiles = walk(nextDir).filter((path) =>
  /(\(share\)|shared-report|\/share\/|share_\[shareId\]|shareId)/i.test(path),
);

if (!shareFiles.length) {
  console.error("assert-share-route: no built share-route files found");
  process.exit(1);
}

const clerkRe = /clerk\.(com|accounts\.dev)|ClerkProvider|@clerk\/nextjs/i;
let sawClientHash = false;
const clerkHits = [];

for (const file of shareFiles) {
  if (!/\.(js|html|rsc|json)$/.test(file)) continue;
  if (file.endsWith(".map")) continue;
  const text = readFileSync(file, "utf8");
  if (clerkRe.test(text)) {
    clerkHits.push(file);
  }
  if (text.includes("location.hash") && text.includes("replaceState")) {
    sawClientHash = true;
  }
}

if (clerkHits.length) {
  console.error("assert-share-route: Clerk resources found in share build:");
  for (const file of clerkHits) console.error(`  ${file}`);
  process.exit(1);
}

if (!sawClientHash) {
  console.error("assert-share-route: client hash capture was not present in share build");
  process.exit(1);
}

console.log(
  `assert-share-route: ok (${shareFiles.length} share files, no Clerk hosts)`,
);
