import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function read(rel) {
  return readFileSync(join(root, rel), "utf8");
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const m44 = read("app/(app)/dashboard/finding-ownership-review-panel.tsx");
const m46 = read("app/(app)/dashboard/finding-follow-up-review-panel.tsx");
const m45 = read("app/(app)/dashboard/finding-ownership-assign-modal.tsx");
const m47 = read("app/(app)/dashboard/finding-follow-up-due-modal.tsx");
const bulkModal = read(
  "app/(app)/dashboard/finding-ownership-bulk-assign-modal.tsx",
);
const helper = read("lib/bulk-ownership-assign.ts");
const api = read("lib/api.ts");

assert(m44.includes('type="checkbox"'), "M44 has per-row checkboxes");
assert(m44.includes("Select visible"), "M44 has Select visible");
assert(m44.includes("selected"), "M44 shows selected count");
assert(m44.includes("Assign selected"), "M44 has Assign selected");
assert(m44.includes("setSelectedIds([])"), "replaced payload clears selection");
assert(m44.includes("invalidateBulk"), "filter/org/page invalidates selection");
assert(m44.includes("postBulkOwnershipAssign") === false, "M44 panel does not POST");
assert(
  m44.includes("FindingOwnershipBulkAssignModal"),
  "M44 hosts the bulk modal",
);
assert(!m46.includes("Assign selected"), "M46 has no Assign selected");
assert(
  !m46.includes("postBulkOwnershipAssign"),
  "M46 does not call bulk ownership assign",
);
assert(
  !m46.includes("FindingOwnershipBulkAssignModal"),
  "M46 does not host the ownership bulk modal",
);
assert(
  !m45.includes("postBulkOwnershipAssign"),
  "M45 does not call bulk assign",
);
assert(
  !m45.includes("expected_follow_up"),
  "M45 remains last-write-wins without expected_follow_up",
);
assert(
  helper.includes("return bulkAssignFindingOwnership(token, body)"),
  "helper posts through bulkAssignFindingOwnership",
);
assert(
  !/\bretry\b/i.test(helper),
  "helper must not retry the bulk POST",
);
assert(
  helper.split("bulkAssignFindingOwnership(").length === 2,
  "helper calls bulkAssignFindingOwnership exactly once",
);
assert(
  bulkModal.includes("postBulkOwnershipAssign"),
  "bulk modal uses the no-retry helper",
);
assert(
  !bulkModal.includes("updateFindingFollowUp("),
  "bulk modal does not call M45 PUT helper",
);
assert(
  !bulkModal.includes("updateFindingFollowUpConditionally"),
  "bulk modal does not call M47 PUT helper",
);
assert(
  bulkModal.includes("isTransportAmbiguousError"),
  "bulk modal uses M47-style transport-uncertain handling",
);
assert(
  bulkModal.includes(
    "Bulk assignment outcome could not be confirmed. Ownership review was refreshed.",
  ),
  "uncertain POST copy is pinned",
);
assert(
  bulkModal.includes("saveInFlightRef"),
  "duplicate submit is blocked",
);
assert(
  bulkModal.includes("Existing") &&
    bulkModal.includes("follow-up due dates will not change"),
  "modal states due dates will not change",
);
assert(
  api.includes("/v1/findings/ownership-review/bulk-assign"),
  "API helper targets the M49 endpoint",
);
assert(
  api.includes("export function bulkAssignFindingOwnership"),
  "API exports bulkAssignFindingOwnership",
);
assert(
  !m47.includes("postBulkOwnershipAssign"),
  "M47 is unchanged by bulk ownership",
);

console.log("assert-bulk-ownership-assign: ok");
