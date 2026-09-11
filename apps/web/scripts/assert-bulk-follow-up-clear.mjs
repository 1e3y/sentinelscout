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

function count(source, needle) {
  return source.split(needle).length - 1;
}

const ownership = read("app/(app)/dashboard/finding-ownership-review-panel.tsx");
const followUp = read("app/(app)/dashboard/finding-follow-up-review-panel.tsx");
const modal = read(
  "app/(app)/dashboard/finding-follow-up-bulk-clear-modal.tsx",
);
const helper = read("lib/bulk-follow-up-clear.ts");
const api = read("lib/api.ts");
const m49Modal = read(
  "app/(app)/dashboard/finding-ownership-bulk-assign-modal.tsx",
);
const m50Modal = read(
  "app/(app)/dashboard/finding-follow-up-bulk-due-modal.tsx",
);
const m52Modal = read(
  "app/(app)/dashboard/finding-follow-up-bulk-edit-modal.tsx",
);

assert(
  count(ownership, "useState<string[]>([])") === 1 &&
    ownership.includes("selectedIds") &&
    ownership.includes("Unassign selected") &&
    ownership.includes("Assign selected"),
  "M44 reuses the one selectedIds collection for Unassign selected",
);
assert(
  ownership.includes('surface: "ownership-review"') &&
    ownership.includes("clear_owner: true") &&
    ownership.includes("clear_due: false"),
  "M44 Unassign selected captures owner-only clear flags",
);
assert(
  ownership.includes("Object.freeze({") &&
    ownership.includes("expected_follow_up: Object.freeze({") &&
    ownership.includes("bulkClearIntentRef.current = intent") &&
    ownership.includes("item.assignee?.user_id ?? null") &&
    ownership.includes("follow_up_due_at: item.follow_up_due_at"),
  "M44 open captures an immutable exact-row expected snapshot",
);
assert(
  ownership.includes("bulkClearSubmitGeneration") &&
    ownership.includes("bulkClearModalGeneration") &&
    ownership.includes("bulkEpoch") &&
    !helper.includes("bulkEpoch"),
  "M44 M53 generations are independent from the M49 bulk epoch",
);
assert(
  !m49Modal.includes("postBulkFollowUpClear") &&
    !ownership.includes("postBulkFollowUpClear"),
  "M49 assign modal does not call the M53 helper",
);

assert(
  count(followUp, "useState<string[]>([])") === 1 &&
    followUp.includes("selectedIds") &&
    followUp.includes("Clear due dates for selected") &&
    followUp.includes("Clear follow-up for selected") &&
    followUp.includes('openBulkClear("due")') &&
    followUp.includes('openBulkClear("both")'),
  "M46 reuses the one selectedIds collection for both clear actions",
);
assert(
  followUp.includes('surface: "follow-up-review"') &&
    followUp.includes('clear_owner: mode !== "due"') &&
    followUp.includes('clear_due: mode !== "owner"'),
  "M46 clear modes map onto the immutable intent flags",
);
assert(
  followUp.includes("Object.freeze({") &&
    followUp.includes("expected_follow_up: Object.freeze({") &&
    followUp.includes("bulkClearIntentRef.current = intent"),
  "M46 open captures an immutable exact-row expected snapshot",
);
assert(
  followUp.includes("bulkClearSubmitGeneration") &&
    followUp.includes("bulkDueEpoch") &&
    followUp.includes("bulkEditSubmitGeneration") &&
    !m50Modal.includes("postBulkFollowUpClear") &&
    !m52Modal.includes("postBulkFollowUpClear") &&
    !m50Modal.includes("bulkClear") &&
    !m52Modal.includes("bulkClear"),
  "M50 and M52 generations and helpers stay isolated from M53",
);

for (const field of [
  "organizationId",
  "targetId",
  "severity",
  "status",
  "cursor",
  "generation",
  "dueState",
]) {
  assert(
    helper.includes(`left.${field} === right.${field}`),
    `clear identity compares semantic ${field}`,
  );
}
assert(
  helper.includes("left.surface === right.surface") &&
    helper.includes("left.submitGeneration === right.submitGeneration") &&
    helper.includes("left.modalGeneration === right.modalGeneration"),
  "complete identity compares surface and independent generations",
);
assert(
  !helper.includes("left === right") &&
    !ownership.includes("intent ===") &&
    !followUp.includes("intent ==="),
  "intent checks never rely on object identity",
);

assert(
  modal.includes("items: immutableIntentItems") &&
    modal.includes("const immutableIntentItems = intent.items") &&
    modal.includes("clear_owner: clearOwner") &&
    modal.includes("clear_due: clearDue") &&
    !modal.includes("selectedIds") &&
    !modal.includes("payload"),
  "save body uses immutable intent rows, never live selection or payload",
);
assert(
  !modal.includes("OrganizationMemberPicker") &&
    !modal.includes("datetime-local") &&
    modal.includes("Owner will be removed. Due dates will stay unchanged.") &&
    modal.includes("Due dates will be cleared. Owners will stay unchanged.") &&
    modal.includes("Owners and due dates will be cleared."),
  "one confirmation modal has no pickers and states what is cleared",
);

assert(
  ownership.includes("invalidateBulkClearIntent();\n    setSelectedIds") &&
    ownership.includes("Select visible") &&
    ownership.includes("Clear selection") &&
    ownership.includes("setTargetId(value)") &&
    ownership.includes("setSeverity(value)") &&
    ownership.includes("setStatus(value)") &&
    ownership.includes("load(payload.next_cursor)") &&
    ownership.includes("Refresh") &&
    ownership.includes("bulkClearIntentRef.current = null"),
  "M44 selection, filters, pages, replacement, close, and unmount invalidate intent",
);
assert(
  followUp.includes("invalidateBulkClearIntent();\n      invalidateBulkEditIntent()") &&
    followUp.includes("invalidateBulkEditIntent();\n      setSelectedIds") &&
    followUp.includes("Select visible") &&
    followUp.includes("Clear selection") &&
    followUp.includes("setFilter(option.value)") &&
    followUp.includes("setTargetId(value)") &&
    followUp.includes("dueState") &&
    followUp.includes("onClick={() => load(payload.next_cursor)}") &&
    followUp.includes("Refresh") &&
    followUp.includes("bulkClearIntentRef.current = null"),
  "M46 selection, due-state, filters, pages, replacement, close, and unmount invalidate intent",
);

assert(
  modal.includes("activeRef.current = false") &&
    modal.includes("localGenerationRef.current += 1") &&
    modal.includes("onClick={closeCurrentModal}") &&
    modal.includes("if (!isCurrent(localGeneration)) return;"),
  "cancel and close synchronously invalidate local and parent intent",
);
assert(
  count(modal, "if (!isCurrent(localGeneration)) return;") >= 8,
  "all submit, callback, and reconciliation awaits are fenced",
);
assert(
  modal.includes("mountedRef.current &&") &&
    modal.includes("activeRef.current &&") &&
    modal.includes("isIntentCurrent(intent)"),
  "every local fence includes mounted, local generation, and parent intent",
);
assert(
  modal.indexOf("const token = await getToken()") <
    modal.indexOf("await postBulkFollowUpClear") &&
    modal.includes("if (!isCurrent(localGeneration)) return;\n      const response"),
  "close before POST sends nothing",
);
assert(
  count(modal, "postBulkFollowUpClear(token,") === 1 &&
    !/\bretry\b/i.test(helper),
  "submit performs exactly one no-retry POST",
);
assert(
  modal.includes("saveInFlightRef.current") &&
    modal.includes("saveInFlightRef.current ||"),
  "double click is fenced to one POST",
);

assert(
  modal.includes("parsed.status === 404 || parsed.status === 409") &&
    ownership.includes("handleBulkClearConflict") &&
    followUp.includes("handleBulkClearConflict") &&
    ownership.includes("select findings again") &&
    followUp.includes("select findings again"),
  "authoritative conflicts clear intent and require a fresh selection",
);
assert(
  modal.includes("parsed.status === 422") &&
    modal.includes("parsed.status === 429") &&
    !modal.includes("STALE_OWNER") &&
    !modal.includes("PROVIDER_UNAVAILABLE"),
  "422/429 stay in-modal with no membership 400/502 mapping",
);
assert(
  modal.includes("isTransportAmbiguousError") &&
    ownership.includes("handleBulkClearTransportUncertain") &&
    followUp.includes("handleBulkClearTransportUncertain") &&
    ownership.includes("outcome could not be confirmed") &&
    followUp.includes("outcome could not be confirmed"),
  "ambiguous transport has neutral copy and one reconciliation path",
);

const ownershipSuccess = ownership.indexOf(
  'setSuccess(\n        response.changed_count === 0',
);
const ownershipRefresh = ownership.indexOf(
  "const refresh = refreshAfterMutation();",
  ownershipSuccess,
);
assert(
  ownershipSuccess >= 0 &&
    ownershipRefresh > ownershipSuccess &&
    ownership.includes(
      "Owners were removed, but ownership review could not be refreshed.",
    ),
  "M44 success is recorded before refresh and refresh failure preserves a warning",
);
const followUpSuccess = followUp.indexOf(
  'setSuccess(\n        response.changed_count === 0',
);
const followUpRefresh = followUp.indexOf(
  "const refresh = refreshFirstPageCurrent();",
  followUpSuccess,
);
assert(
  followUpSuccess >= 0 &&
    followUpRefresh > followUpSuccess &&
    followUp.includes(
      "Follow-up was cleared, but the follow-up review could not be refreshed.",
    ),
  "M46 success is recorded before refresh and refresh failure preserves a warning",
);

assert(
  api.includes('"/v1/findings/follow-up-review/bulk-clear"') &&
    api.includes("export function bulkClearFindingFollowUp") &&
    helper.includes("return bulkClearFindingFollowUp(token, body)"),
  "API and no-retry helper target the M53 endpoint",
);

console.log("assert-bulk-follow-up-clear: ok");
