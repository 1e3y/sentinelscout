import {
  bulkClearFindingFollowUp,
  type BulkFollowUpClearRequest,
  type BulkFollowUpClearResponse,
} from "@/lib/api";

export type BulkFollowUpClearMode = "owner" | "due" | "both";
export type BulkFollowUpClearSurface =
  | "ownership-review"
  | "follow-up-review";

export type BulkFollowUpClearReviewSnapshot = {
  organizationId: string | null;
  targetId: string | null;
  severity: string | null;
  status: string | null;
  cursor: string | null;
  generation: number;
  dueState?: string | null;
};

export type BulkFollowUpClearItem = {
  finding_id: string;
  expected_follow_up: {
    assigned_to_user_id: string | null;
    follow_up_due_at: string | null;
  };
};

export type BulkFollowUpClearIdentity = {
  surface: BulkFollowUpClearSurface;
  organizationId: string;
  reviewSnapshot: BulkFollowUpClearReviewSnapshot;
  submitGeneration: number;
  modalGeneration: number;
};

export type BulkFollowUpClearIntent = BulkFollowUpClearIdentity & {
  selectedCount: number;
  items: readonly BulkFollowUpClearItem[];
  clear_owner: boolean;
  clear_due: boolean;
};

export function sameBulkFollowUpClearReviewSnapshot(
  left: BulkFollowUpClearReviewSnapshot,
  right: BulkFollowUpClearReviewSnapshot,
): boolean {
  return (
    left.organizationId === right.organizationId &&
    left.targetId === right.targetId &&
    left.severity === right.severity &&
    left.status === right.status &&
    left.cursor === right.cursor &&
    left.generation === right.generation &&
    left.dueState === right.dueState
  );
}

export function sameBulkFollowUpClearIdentity(
  left: BulkFollowUpClearIdentity,
  right: BulkFollowUpClearIdentity,
): boolean {
  return (
    left.surface === right.surface &&
    left.organizationId === right.organizationId &&
    left.submitGeneration === right.submitGeneration &&
    left.modalGeneration === right.modalGeneration &&
    sameBulkFollowUpClearReviewSnapshot(left.reviewSnapshot, right.reviewSnapshot)
  );
}

export function postBulkFollowUpClear(
  token: string,
  body: BulkFollowUpClearRequest,
): Promise<BulkFollowUpClearResponse> {
  return bulkClearFindingFollowUp(token, body);
}
