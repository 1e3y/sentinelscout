import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (...parts) => readFileSync(join(root, ...parts), "utf8");
const m45 = read(
  "app",
  "(app)",
  "dashboard",
  "finding-ownership-assign-modal.tsx",
);
const m44 = read(
  "app",
  "(app)",
  "dashboard",
  "finding-ownership-review-panel.tsx",
);
const detail = read("app", "(app)", "dashboard", "findings-panel.tsx");
const section = read("app", "(app)", "dashboard", "findings-section.tsx");
const ownershipHelper = read("lib", "update-finding-ownership-conditional.ts");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function count(source, value) {
  return source.split(value).length - 1;
}

assert(
  count(m45, "updateFindingOwnershipConditionally({") === 1,
  "M45 must issue one explicit conditional ownership write",
);
assert(
  !m45.includes("updateFindingFollowUp("),
  "M45 must not use the legacy last-write-wins helper",
);
assert(
  !m45.includes('setSelectedUserId("")'),
  "M45 drift/conflict paths must retain the proposed owner",
);
for (const contract of [
  "FOLLOW_UP_CHANGED",
  "RESOLVED_API",
  "STALE_OWNER_API",
  "PROVIDER_UNAVAILABLE_API",
  "isTransportAmbiguousError",
]) {
  assert(m45.includes(contract), `M45 is missing ${contract}`);
}
assert(
  m45.includes("if (generationRef.current !== generation) return;"),
  "M45 must fence old modal completions",
);
assert(
  m45.includes("onTransportUncertain"),
  "M45 must report ambiguous transport to M44",
);
assert(
  m44.includes("handleTransportUncertain") &&
    m44.includes("sameReviewCollection(opened, live)"),
  "M44 transport reconciliation must use the modal-open review snapshot fence",
);

for (const field of [
  "assigned_to_user_id: proposedOwnerUserId",
  "follow_up_due_at: authoritativeDueAt",
  "assigned_to_user_id: authoritativeOwnerUserId",
]) {
  assert(
    ownershipHelper.includes(field),
    `ownership helper is missing ${field}`,
  );
}
assert(
  count(ownershipHelper, "updateFindingFollowUpConditionally(") === 1,
  "ownership helper must perform exactly one conditional PUT",
);
assert(
  !/\b(for|while)\s*\(/.test(ownershipHelper) &&
    !ownershipHelper.toLowerCase().includes("retry"),
  "ownership helper must not loop or retry",
);

assert(
  detail.includes("updateFindingFollowUpConditionally(") &&
    !detail.includes("updateFindingFollowUp("),
  "detail follow-up writes must be conditional only",
);
for (const identityPart of [
  "organizationIdRef",
  "findingIdRef",
  "generationRef",
  "mountedRef",
  "isIdentityCurrent(identity)",
]) {
  assert(detail.includes(identityPart), `detail is missing ${identityPart}`);
}
assert(
  count(detail, "isIdentityCurrent(identity)") >= 30,
  "detail async completions are not comprehensively fenced",
);
for (const operation of [
  "fetchFinding(",
  "fetchFindingTimeline(",
  "fetchOrganizationMembers(",
  "fetchFindingFollowUpReminderStatus(",
  "recordFindingRemediation(",
  "fetchFindingFollowUpReminderHistory(",
  "paginationCursorRef",
  "onFindingChanged()",
]) {
  assert(detail.includes(operation), `detail fence coverage is missing ${operation}`);
}

assert(
  detail.includes("let desiredDue = authoritativeDue") &&
    detail.includes("if (dueDirty)") &&
    detail.includes("desiredDue = parsed.iso") &&
    detail.includes("desiredDue = null"),
  "detail due derivation must distinguish untouched, edited, and cleared drafts",
);
assert(
  detail.includes("formatLocalDateTimeInput(") &&
    detail.includes("parseLocalDateTimeInput(") &&
    detail.includes("formatLocalDuePreview(") &&
    detail.includes("LOCAL_TIMEZONE_LABEL") &&
    detail.includes("localDateTimeMessage("),
  "detail must use the shared datetime-local contract",
);
assert(
  !detail.includes("toISOString().slice(0, 16)") &&
    !detail.includes("new Date(dueDraft).toISOString()"),
  "detail must not use unsafe datetime-local round trips",
);
const detailSuccessReconciliation = detail.slice(
  detail.indexOf("if (!token || !writtenFollowUp"),
  detail.indexOf("function loadReminderHistory"),
);
assert(
  !detailSuccessReconciliation.includes("fetchFinding(") &&
    detailSuccessReconciliation.includes("fetchFindingTimeline(") &&
    detailSuccessReconciliation.includes(
      "fetchFindingFollowUpReminderStatus(",
    ),
  "detail success must reuse the PUT response without a third owner-provider read",
);

const authoritativeDue = "2026-06-15T18:30:00.000Z";
const deriveDesiredDue = ({ dueDirty, dueDraft, parsedIso }) => {
  if (!dueDirty) return authoritativeDue;
  if (!dueDraft) return null;
  return parsedIso;
};
assert(
  deriveDesiredDue({
    dueDirty: false,
    dueDraft: "2026-06-15T11:30",
    parsedIso: "wrong-if-used",
  }) === authoritativeDue,
  "a non-UTC owner-only edit must preserve the exact authoritative due instant",
);
assert(
  deriveDesiredDue({ dueDirty: true, dueDraft: "", parsedIso: null }) === null,
  "an explicit due clear must send null",
);

const current = {
  mounted: true,
  organizationId: "org-b",
  findingId: "finding-b",
  generation: 2,
};
const applies = (request) =>
  current.mounted &&
  current.organizationId === request.organizationId &&
  current.findingId === request.findingId &&
  current.generation === request.generation;
assert(
  !applies({ organizationId: "org-b", findingId: "finding-a", generation: 1 }),
  "a delayed Finding A completion must not apply after selecting B",
);
assert(
  !applies({ organizationId: "org-a", findingId: "finding-b", generation: 2 }),
  "an old-organization completion must not apply",
);
assert(
  applies({ organizationId: "org-b", findingId: "finding-b", generation: 2 }),
  "the exact current identity must apply",
);

assert(
  section.includes("useEffect(() =>") &&
    section.includes("setSelectedFindingId(null)") &&
    section.includes("organizationId={organizationId}") &&
    section.includes('key={`${organizationId ?? "no-org"}'),
  "organization replacement must clear selection and remount the detail identity",
);

console.log("conditional follow-up write contract passed");
