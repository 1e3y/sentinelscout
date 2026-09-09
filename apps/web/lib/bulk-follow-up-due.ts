import {
  bulkUpdateFindingFollowUpDue,
  type BulkFollowUpDueRequest,
  type BulkFollowUpDueResponse,
} from "@/lib/api";

export function postBulkFollowUpDue(
  token: string,
  body: BulkFollowUpDueRequest,
): Promise<BulkFollowUpDueResponse> {
  return bulkUpdateFindingFollowUpDue(token, body);
}
