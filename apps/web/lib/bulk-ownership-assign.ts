import {
  bulkAssignFindingOwnership,
  type BulkOwnershipAssignRequest,
  type BulkOwnershipAssignResponse,
} from "@/lib/api";

export function postBulkOwnershipAssign(
  token: string,
  body: BulkOwnershipAssignRequest,
): Promise<BulkOwnershipAssignResponse> {
  return bulkAssignFindingOwnership(token, body);
}
