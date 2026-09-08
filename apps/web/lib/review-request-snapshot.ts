/** Bind review responses to the exact filter snapshot that launched them. */

export type ReviewDimensionSnapshot = {
  organizationId: string | null;
  targetId: string | null;
  severity: string | null;
  status: string | null;
  cursor: string | null;
};

export type OwnershipReviewRequestSnapshot = ReviewDimensionSnapshot & {
  generation: number;
};

export type FollowUpReviewRequestSnapshot = OwnershipReviewRequestSnapshot & {
  dueState: string | null;
};

function dueStateOf(
  snapshot: OwnershipReviewRequestSnapshot | FollowUpReviewRequestSnapshot,
): string | null {
  if ("dueState" in snapshot) {
    return snapshot.dueState ?? null;
  }
  return null;
}

export function sameReviewDimensions(
  left: ReviewDimensionSnapshot,
  right: ReviewDimensionSnapshot,
): boolean {
  return (
    left.organizationId === right.organizationId &&
    left.targetId === right.targetId &&
    left.severity === right.severity &&
    left.status === right.status
  );
}

export function sameReviewCollection<
  T extends OwnershipReviewRequestSnapshot | FollowUpReviewRequestSnapshot,
>(left: T, right: T): boolean {
  if (!sameReviewDimensions(left, right)) return false;
  if ("dueState" in left || "dueState" in right) {
    return dueStateOf(left) === dueStateOf(right);
  }
  return true;
}

export function sameReviewPage(
  left: ReviewDimensionSnapshot,
  right: ReviewDimensionSnapshot,
): boolean {
  return sameReviewDimensions(left, right) && left.cursor === right.cursor;
}

export function ownershipRefreshCursor(
  opened: ReviewDimensionSnapshot | null,
  live: ReviewDimensionSnapshot,
): string | null {
  if (opened && sameReviewPage(opened, live)) return live.cursor;
  return null;
}

export function shouldApplyReviewResponse<
  T extends OwnershipReviewRequestSnapshot,
>(current: T, request: T): boolean {
  if (current.generation !== request.generation) return false;
  if (!sameReviewCollection(current, request)) return false;
  if (current.cursor !== request.cursor) return false;
  return true;
}

export function shouldApplyReviewResult<
  T extends OwnershipReviewRequestSnapshot,
>(args: {
  mounted: boolean;
  latest: T | null;
  live: T;
  request: T;
}): boolean {
  if (!args.mounted || args.latest == null) return false;
  if (!shouldApplyReviewResponse(args.latest, args.request)) return false;
  if (args.live.generation !== args.request.generation) return false;
  return sameReviewCollection(args.live, args.request);
}
