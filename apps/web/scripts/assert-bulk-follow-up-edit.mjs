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

const panel = read("app/(app)/dashboard/finding-follow-up-review-panel.tsx");
const modal = read(
  "app/(app)/dashboard/finding-follow-up-bulk-edit-modal.tsx",
);
const m50Modal = read(
  "app/(app)/dashboard/finding-follow-up-bulk-due-modal.tsx",
);
const helper = read("lib/bulk-follow-up-edit.ts");
const api = read("lib/api.ts");
const datetime = read("lib/datetime-local.ts");

assert(
  count(panel, "useState<string[]>([])") === 1 &&
    panel.includes("openBulkDue") &&
    panel.includes("openBulkEdit") &&
    panel.includes("selectedIds"),
  "M50 and M52 share the one selectedIds collection",
);
assert(
  panel.includes("Set due date for selected") &&
    panel.includes("Edit follow-up for selected"),
  "both independent selected-finding actions are present",
);
for (const field of [
  "organizationId",
  "reviewSnapshot",
  "selectedCount",
  "items",
  "submitGeneration",
  "modalGeneration",
]) {
  assert(panel.includes(field), `immutable intent captures ${field}`);
}
assert(
  panel.includes("Object.freeze({") &&
    panel.includes("expected_follow_up: Object.freeze({") &&
    panel.includes("bulkEditIntentRef.current = intent"),
  "open captures an immutable exact-row intent",
);
assert(
  panel.includes("item.assignee?.user_id ?? null") &&
    panel.includes("follow_up_due_at: item.follow_up_due_at"),
  "intent captures displayed expected owner and due values",
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
    `review identity compares semantic ${field}`,
  );
}
assert(
  helper.includes("left.submitGeneration === right.submitGeneration") &&
    helper.includes("left.modalGeneration === right.modalGeneration"),
  "complete identity compares independent submit and modal generations",
);
assert(
  !helper.includes("left === right") && !panel.includes("intent ==="),
  "intent checks never rely on object identity",
);
assert(
  modal.includes("items: immutableIntentItems") &&
    modal.includes("const immutableIntentItems = intent.items") &&
    !modal.includes("selectedIds") &&
    !modal.includes("payload"),
  "save body uses immutable intent rows, never live selection or payload",
);
assert(
  modal.includes("assigned_to_user_id: proposedOwner") &&
    modal.includes("follow_up_due_at: proposedDue"),
  "save adds only proposed owner and due values",
);
assert(
  panel.includes("invalidateBulkEditIntent();\n      setSelectedIds") &&
    panel.includes("Select visible") &&
    panel.includes("Clear selection") &&
    panel.includes("setFilter(option.value)") &&
    panel.includes("setTargetId(value)") &&
    panel.includes("setSeverity(value)") &&
    panel.includes("setStatus(value)") &&
    panel.includes("onClick={() => load(payload.next_cursor)}") &&
    panel.includes("bulkEditIntentRef.current = null"),
  "selection, filters, pages, replacement, close, and unmount invalidate intent",
);
assert(
  panel.includes("bulkEditModalGenerationRef.current = modalGeneration") &&
    panel.includes("sameBulkFollowUpEditIdentity(intent, currentIntent)") &&
    panel.includes("sameBulkFollowUpEditIdentity(intent, liveIdentity)"),
  "modal replacement and parent live context fence stale completions",
);
assert(
  modal.includes("activeRef.current = false") &&
    modal.includes("localGenerationRef.current += 1") &&
    modal.includes("onClick={closeCurrentModal}") &&
    modal.includes("if (!isCurrent(localGeneration)) return;"),
  "cancel and close synchronously invalidate local and parent intent",
);
assert(
  count(modal, "if (!isCurrent(localGeneration)) return;") >= 10,
  "all members, submit, callback, and reconciliation awaits are fenced",
);
assert(
  modal.includes("mountedRef.current &&") &&
    modal.includes("activeRef.current &&") &&
    modal.includes("isIntentCurrent(intent)"),
  "every local fence includes mounted, local generation, and parent intent",
);
assert(
  modal.indexOf("const token = await getToken()") <
    modal.indexOf("await postBulkFollowUpEdit") &&
    modal.includes("if (!isCurrent(localGeneration)) return;\n      const response"),
  "close before POST sends nothing",
);
assert(
  modal.includes("const response = await postBulkFollowUpEdit") &&
    modal.includes(
      "const response = await postBulkFollowUpEdit(token, {\n" +
        "        assigned_to_user_id: proposedOwner",
    ) &&
    count(modal, "postBulkFollowUpEdit(token,") === 1 &&
    !/\bretry\b/i.test(helper),
  "submit performs exactly one no-retry POST",
);
assert(
  modal.includes("saveInFlightRef.current") &&
    modal.includes("saveInFlightRef.current ||"),
  "double click is fenced to one POST",
);
assert(
  modal.includes("fetchOrganizationMembers") &&
    modal.includes("page_size: MEMBER_PAGE_SIZE") &&
    modal.includes("cursor,") &&
    modal.includes("<OrganizationMemberPicker"),
  "member picker reuses paginated organization-member reads",
);
assert(
  modal.includes("type=\"datetime-local\"") &&
    modal.includes("required") &&
    modal.includes("parseLocalDateTimeInput") &&
    modal.includes("localDateTimeMessage") &&
    modal.includes("formatLocalDuePreview") &&
    datetime.includes('"nonexistent"') &&
    datetime.includes('"ambiguous"') &&
    datetime.includes("candidate.toISOString()"),
  "required due input rejects invalid DST times and preserves its instant",
);
assert(
  modal.includes(
    "parsed.status === 400 && parsed.message === STALE_OWNER_API",
  ) &&
    modal.includes("parsed.status === 502") &&
    modal.includes("parsed.message === PROVIDER_UNAVAILABLE_API") &&
    modal.includes("setError(UPDATE_FAILED)"),
  "only exact membership errors receive specific copy; others stay generic",
);
assert(
  modal.includes("parsed.status === 404 || parsed.status === 409") &&
    panel.includes("handleBulkEditConflict") &&
    panel.includes("select findings again"),
  "authoritative conflicts clear intent and require a fresh selection",
);
assert(
  modal.includes("isTransportAmbiguousError") &&
    count(panel, "handleBulkEditTransportUncertain") === 2 &&
    panel.includes("outcome could not be confirmed") &&
    !panel.includes("Bulk follow-up edit succeeded"),
  "ambiguous transport has neutral copy and one reconciliation path",
);
const successIndex = panel.indexOf(
  'setSuccess(\n        response.changed_count === 0',
);
const successRefreshIndex = panel.indexOf(
  "const refresh = refreshFirstPageCurrent();",
  successIndex,
);
assert(
  successIndex >= 0 &&
    successRefreshIndex > successIndex &&
    panel.includes(
      "Follow-up was updated, but the follow-up review could not be refreshed.",
    ),
  "success is recorded before refresh and refresh failure preserves a warning",
);
assert(
  panel.includes("bulkDueEpoch") &&
    panel.includes("bulkEditSubmitGeneration") &&
    panel.includes("handleBulkDueWriteSucceeded") &&
    panel.includes("handleBulkEditWriteSucceeded") &&
    !m50Modal.includes("postBulkFollowUpEdit") &&
    !modal.includes("postBulkFollowUpDue"),
  "M50 and M52 generations, results, and write helpers stay isolated",
);
assert(
  api.includes('"/v1/findings/follow-up-review/bulk-edit"') &&
    api.includes("export function bulkEditFindingFollowUp") &&
    helper.includes("return bulkEditFindingFollowUp(token, body)"),
  "API and no-retry helper target the M52 endpoint",
);

console.log("assert-bulk-follow-up-edit: ok");
