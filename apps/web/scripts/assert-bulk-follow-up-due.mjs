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
const m47 = read("app/(app)/dashboard/finding-follow-up-due-modal.tsx");
const modal = read(
  "app/(app)/dashboard/finding-follow-up-bulk-due-modal.tsx",
);
const helper = read("lib/bulk-follow-up-due.ts");
const api = read("lib/api.ts");

assert(m46.includes('type="checkbox"'), "M46 has per-row due selection");
assert(m46.includes("Select visible"), "M46 has Select visible");
assert(m46.includes("selectedIds.length} selected"), "M46 shows selected count");
assert(
  m46.includes("Set due date for selected"),
  "M46 has the bulk due action",
);
assert(
  m46.includes("FindingFollowUpBulkDueModal"),
  "M46 hosts the bulk due modal",
);
assert(
  m46.includes("item.assignee?.user_id ?? null") &&
    m46.includes("follow_up_due_at: item.follow_up_due_at"),
  "M46 sends selected row expected owner and due",
);
assert(
  m46.includes("evaluationTime: payload.evaluation_time"),
  "modal intent binds the applied evaluation time",
);
assert(
  m46.includes("invalidateBulkDue"),
  "M46 invalidates selection on view replacement",
);
assert(
  m46.includes("reviewReplacing || selectedIds.length === 0"),
  "replacement loading disables the bulk action",
);
assert(
  m46.includes("disabled={reviewReplacing}"),
  "replacement loading disables row and visible selection",
);
assert(
  m46.includes("reviewReplacementRef.current === replacement"),
  "only the current replacement request ends loading",
);
assert(
  m46.includes("generationRef.current += 1") &&
    m46.includes("currentSnapshot(null)"),
  "authoritative refresh requests page one with a new generation",
);
assert(
  !m44.includes("FindingFollowUpBulkDueModal") &&
    !m44.includes("postBulkFollowUpDue"),
  "M44 has no bulk due behavior",
);
assert(
  !m47.includes("postBulkFollowUpDue"),
  "M47 remains independent from bulk due",
);
assert(
  helper.includes("return bulkUpdateFindingFollowUpDue(token, body)"),
  "bulk due helper posts through the API function",
);
assert(!/\bretry\b/i.test(helper), "bulk due helper must not retry");
assert(
  helper.split("bulkUpdateFindingFollowUpDue(").length === 2,
  "bulk due helper calls the API exactly once",
);
assert(
  modal.includes("postBulkFollowUpDue"),
  "bulk due modal uses the no-retry helper",
);
assert(modal.includes("saveInFlightRef"), "duplicate submit is blocked");
assert(
  modal.includes("Current owners will not change") &&
    modal.includes("due dates only"),
  "modal states owners will not change",
);
assert(
  modal.includes(
    'parsed.status === 400 && parsed.message === STALE_OWNER_API',
  ),
  "only the exact stale-owner 400 is reclassified",
);
assert(
  modal.includes("parsed.status === 502") &&
    modal.includes("parsed.message === PROVIDER_UNAVAILABLE_API"),
  "only the exact provider 502 is reclassified",
);
assert(
  modal.includes("isTransportAmbiguousError"),
  "transport ambiguity is handled without retry",
);
assert(
  !modal.includes("updateFindingFollowUp(") &&
    !modal.includes("updateFindingFollowUpConditionally"),
  "bulk modal never loops single-Finding writes",
);
assert(
  api.includes("/v1/findings/follow-up-review/bulk-due"),
  "API helper targets the M50 endpoint",
);
assert(
  api.includes("export function bulkUpdateFindingFollowUpDue"),
  "API exports the M50 write",
);

console.log("assert-bulk-follow-up-due: ok");
