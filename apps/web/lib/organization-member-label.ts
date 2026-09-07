/** Neutral app-user presentation. Never uses email, Clerk ids, or provider role. */

export function organizationMemberLabel(
  displayName: string | null | undefined,
): string {
  const trimmed = displayName?.trim();
  return trimmed ? trimmed : "Organization member";
}

export function organizationMemberPickerLabel(
  displayName: string | null | undefined,
  userId: string,
  siblings: Array<{ user_id: string; display_name: string | null }>,
): string {
  const base = organizationMemberLabel(displayName);
  const sameLabel = siblings.filter(
    (row) => organizationMemberLabel(row.display_name) === base,
  );
  if (sameLabel.length > 1) {
    return `${base} (${userId.slice(0, 8)})`;
  }
  return base;
}
