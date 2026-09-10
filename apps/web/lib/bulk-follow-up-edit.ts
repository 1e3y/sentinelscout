import {
  bulkEditFindingFollowUp,
  type BulkFollowUpEditRequest,
  type BulkFollowUpEditResponse,
} from "@/lib/api";
import type { FollowUpReviewRequestSnapshot } from "@/lib/review-request-snapshot";

export type BulkFollowUpEditIdentity = {
  organizationId: string;
  reviewSnapshot: FollowUpReviewRequestSnapshot;
  submitGeneration: number;
  modalGeneration: number;
};

export function sameFollowUpReviewSnapshot(
  left: FollowUpReviewRequestSnapshot,
  right: FollowUpReviewRequestSnapshot,
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

export function sameBulkFollowUpEditIdentity(
  left: BulkFollowUpEditIdentity,
  right: BulkFollowUpEditIdentity,
): boolean {
  return (
    left.organizationId === right.organizationId &&
    left.submitGeneration === right.submitGeneration &&
    left.modalGeneration === right.modalGeneration &&
    sameFollowUpReviewSnapshot(left.reviewSnapshot, right.reviewSnapshot)
  );
}

export function postBulkFollowUpEdit(
  token: string,
  body: BulkFollowUpEditRequest,
): Promise<BulkFollowUpEditResponse> {
  return bulkEditFindingFollowUp(token, body);
}
