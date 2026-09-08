import {
  updateFindingFollowUpConditionally,
  type FindingFollowUp,
} from "@/lib/api";

export type ConditionalFindingFollowUpWrite = {
  assigned_to_user_id: string | null;
  follow_up_due_at: string;
  expected_follow_up: {
    assigned_to_user_id: string | null;
    follow_up_due_at: string | null;
  };
};

export function writeFindingFollowUpDueConditionally(
  token: string,
  findingId: string,
  body: ConditionalFindingFollowUpWrite,
): Promise<FindingFollowUp> {
  return updateFindingFollowUpConditionally(token, findingId, {
    assigned_to_user_id: body.assigned_to_user_id,
    follow_up_due_at: body.follow_up_due_at,
    expected_follow_up: {
      assigned_to_user_id: body.expected_follow_up.assigned_to_user_id,
      follow_up_due_at: body.expected_follow_up.follow_up_due_at,
    },
  });
}
