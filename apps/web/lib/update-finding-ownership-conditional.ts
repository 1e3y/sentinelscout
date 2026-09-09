import {
  updateFindingFollowUpConditionally,
  type FindingFollowUp,
} from "@/lib/api";

type OwnershipConditionalWrite = {
  token: string;
  findingId: string;
  proposedOwnerUserId: string;
  authoritativeOwnerUserId: string | null;
  authoritativeDueAt: string | null;
};

/**
 * Change owner, preserve the exact authoritative due instant, and compare both
 * follow-up fields so an intervening owner or due write cannot be overwritten.
 */
export function updateFindingOwnershipConditionally({
  token,
  findingId,
  proposedOwnerUserId,
  authoritativeOwnerUserId,
  authoritativeDueAt,
}: OwnershipConditionalWrite): Promise<FindingFollowUp> {
  return updateFindingFollowUpConditionally(token, findingId, {
    assigned_to_user_id: proposedOwnerUserId,
    follow_up_due_at: authoritativeDueAt,
    expected_follow_up: {
      assigned_to_user_id: authoritativeOwnerUserId,
      follow_up_due_at: authoritativeDueAt,
    },
  });
}
