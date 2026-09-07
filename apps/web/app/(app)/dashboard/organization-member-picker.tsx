"use client";

import { organizationMemberPickerLabel } from "@/lib/organization-member-label";
import type { OrganizationMember } from "@/lib/api";

type Props = {
  members: OrganizationMember[];
  selectedUserId: string;
  disabled: boolean;
  loading: boolean;
  nextCursor: string | null;
  loadingMore: boolean;
  onSelect: (userId: string) => void;
  onLoadMore: () => void;
};

export function OrganizationMemberPicker({
  members,
  selectedUserId,
  disabled,
  loading,
  nextCursor,
  loadingMore,
  onSelect,
  onLoadMore,
}: Props) {
  if (loading) {
    return <p className="text-sm text-zinc-600">Loading organization members…</p>;
  }

  return (
    <div className="space-y-2">
      <label className="block text-sm text-zinc-700">
        <span className="text-zinc-500">New owner</span>
        <select
          className="mt-1 w-full rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
          value={selectedUserId}
          disabled={disabled}
          onChange={(event) => onSelect(event.target.value)}
        >
          <option value="">Select a current member</option>
          {members.map((member) => (
            <option key={member.user_id} value={member.user_id}>
              {organizationMemberPickerLabel(
                member.display_name,
                member.user_id,
                members,
              )}
            </option>
          ))}
        </select>
      </label>
      {nextCursor ? (
        <button
          type="button"
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          disabled={disabled || loadingMore}
          onClick={onLoadMore}
        >
          {loadingMore ? "Loading…" : "Load more"}
        </button>
      ) : null}
    </div>
  );
}
