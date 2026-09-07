import type { FindingResponse } from "@/lib/api";

export type InlineOwnershipSnapshot = {
  finding_id: string;
  status: string;
  owner_user_id: string | null;
  owner_display_name: string | null;
  follow_up_due_at: string | null;
};

export function projectInlineOwnershipSnapshot(
  finding: FindingResponse,
): InlineOwnershipSnapshot {
  return {
    finding_id: finding.id,
    status: finding.status,
    owner_user_id: finding.follow_up?.owner?.user_id ?? null,
    owner_display_name: finding.follow_up?.owner?.display_name ?? null,
    follow_up_due_at: finding.follow_up?.follow_up_due_at ?? null,
  };
}

export function snapshotsOwnerEqual(
  displayed: InlineOwnershipSnapshot,
  fresh: InlineOwnershipSnapshot,
): boolean {
  return displayed.owner_user_id === fresh.owner_user_id;
}

export function snapshotsDueEqual(
  displayed: InlineOwnershipSnapshot,
  fresh: InlineOwnershipSnapshot,
): boolean {
  return displayed.follow_up_due_at === fresh.follow_up_due_at;
}
