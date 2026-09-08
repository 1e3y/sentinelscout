import type { FindingResponse } from "@/lib/api";
import { dueInstantsEqual } from "@/lib/datetime-local";

export type InlineDueDateSnapshot = {
  finding_id: string;
  status: string;
  owner_user_id: string | null;
  owner_display_name: string | null;
  follow_up_due_at: string | null;
};

export function projectInlineDueDateSnapshot(
  finding: FindingResponse,
): InlineDueDateSnapshot {
  return {
    finding_id: finding.id,
    status: finding.status,
    owner_user_id: finding.follow_up?.owner?.user_id ?? null,
    owner_display_name: finding.follow_up?.owner?.display_name ?? null,
    follow_up_due_at: finding.follow_up?.follow_up_due_at ?? null,
  };
}

export function snapshotsOwnerEqual(
  displayed: InlineDueDateSnapshot,
  fresh: InlineDueDateSnapshot,
): boolean {
  return displayed.owner_user_id === fresh.owner_user_id;
}

export function snapshotsDueEqual(
  displayed: InlineDueDateSnapshot,
  fresh: InlineDueDateSnapshot,
): boolean {
  return dueInstantsEqual(displayed.follow_up_due_at, fresh.follow_up_due_at);
}
