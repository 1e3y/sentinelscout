function sameReviewDimensions(left, right) {
  return (
    left.organizationId === right.organizationId &&
    left.targetId === right.targetId &&
    left.severity === right.severity &&
    left.status === right.status
  );
}

function dueStateOf(snapshot) {
  return "dueState" in snapshot ? (snapshot.dueState ?? null) : null;
}

function sameReviewCollection(left, right) {
  if (!sameReviewDimensions(left, right)) return false;
  if ("dueState" in left || "dueState" in right) {
    return dueStateOf(left) === dueStateOf(right);
  }
  return true;
}

function sameReviewPage(left, right) {
  return sameReviewDimensions(left, right) && left.cursor === right.cursor;
}

function ownershipRefreshCursor(opened, live) {
  if (opened && sameReviewPage(opened, live)) return live.cursor;
  return null;
}

function shouldApplyReviewResponse(current, request) {
  if (current.generation !== request.generation) return false;
  if (!sameReviewCollection(current, request)) return false;
  if (current.cursor !== request.cursor) return false;
  return true;
}

function shouldApplyReviewResult({ mounted, latest, live, request }) {
  if (!mounted || latest == null) return false;
  if (!shouldApplyReviewResponse(latest, request)) return false;
  if (live.generation !== request.generation) return false;
  return sameReviewCollection(live, request);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const high = {
  organizationId: "org-a",
  targetId: null,
  severity: "high",
  status: null,
  cursor: null,
  generation: 1,
};
const critical = { ...high, severity: "critical", generation: 2 };
assert(
  shouldApplyReviewResponse(critical, critical),
  "current critical request applies",
);
assert(
  !shouldApplyReviewResponse(critical, high),
  "old high result is ignored after severity change",
);
assert(
  !shouldApplyReviewResult({
    mounted: true,
    latest: critical,
    live: critical,
    request: high,
  }),
  "late high response cannot replace current critical page",
);

const overdueHigh = {
  ...high,
  dueState: "overdue",
  generation: 1,
};
const overdueCritical = {
  ...overdueHigh,
  severity: "critical",
  generation: 2,
};
assert(
  !shouldApplyReviewResponse(overdueCritical, overdueHigh),
  "old overdue/high cannot replace a new evaluation walk",
);
assert(
  !shouldApplyReviewResult({
    mounted: true,
    latest: overdueCritical,
    live: overdueCritical,
    request: overdueHigh,
  }),
  "old M46 evaluation snapshot cannot replace the newer filter walk",
);

const nextA = {
  organizationId: "org-a",
  targetId: null,
  severity: "high",
  status: null,
  cursor: "cursor-c",
  generation: 3,
};
const pageB = {
  ...nextA,
  severity: "low",
  cursor: null,
  generation: 4,
};
assert(
  !shouldApplyReviewResponse(pageB, nextA),
  "late next-page for filter A cannot replace filter B page 1",
);
assert(
  shouldApplyReviewResult({
    mounted: true,
    latest: pageB,
    live: pageB,
    request: pageB,
  }),
  "filter B page 1 remains the current request",
);

const page1 = { ...high, cursor: null, generation: 1 };
const nextSameWalk = { ...high, cursor: "cursor-c", generation: 1 };
assert(
  !shouldApplyReviewResult({
    mounted: true,
    latest: nextSameWalk,
    live: page1,
    request: page1,
  }),
  "late page-1 cannot replace an in-flight next page of the same filters",
);

const orgA = { ...high, organizationId: "org-a", generation: 5 };
const orgB = { ...high, organizationId: "org-b", generation: 6 };
assert(!shouldApplyReviewResponse(orgB, orgA), "org A review cannot overwrite org B");
assert(
  !shouldApplyReviewResult({
    mounted: true,
    latest: orgB,
    live: orgB,
    request: orgA,
  }),
  "late org A target/review response cannot populate org B",
);

const opened = {
  organizationId: "org-a",
  targetId: "target-1",
  severity: "high",
  status: "open",
  cursor: "page-2",
};
const currentB = {
  ...opened,
  severity: "critical",
  cursor: null,
};
assert(!sameReviewPage(opened, currentB), "M45 must not restore modal-open page A");
assert(ownershipRefreshCursor(opened, currentB) === null, "M45 refresh uses current B page 1");
assert(sameReviewDimensions(currentB, currentB), "M47 refresh uses current filters");
assert(
  ownershipRefreshCursor(opened, opened) === "page-2",
  "M45 may refresh the same logical page when filters and cursor are unchanged",
);

const m47Opened = { ...overdueHigh, cursor: "page-2" };
const m47Current = { ...overdueHigh, severity: "low", cursor: null, generation: 9 };
assert(
  ownershipRefreshCursor(m47Opened, m47Current) === null,
  "M47 always starts first page of current filters after write",
);
assert(
  !sameReviewCollection(m47Opened, m47Current),
  "M47 must not reuse the modal-open filter snapshot or evaluation walk",
);

assert(
  !shouldApplyReviewResult({
    mounted: false,
    latest: critical,
    live: critical,
    request: critical,
  }),
  "unmounted components ignore late review responses",
);

console.log("review request snapshot contract passed");
