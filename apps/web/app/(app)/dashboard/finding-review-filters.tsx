"use client";

import type { TargetResponse } from "@/lib/api";

export const SEVERITY_OPTIONS = [
  ["", "All severities"],
  ["informational", "Informational"],
  ["low", "Low"],
  ["medium", "Medium"],
  ["high", "High"],
  ["critical", "Critical"],
] as const;

export const STATUS_OPTIONS = [
  ["", "All active statuses"],
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["ready_for_retest", "Ready for retest"],
] as const;

type Props = {
  targetId: string;
  severity: string;
  status: string;
  targets: TargetResponse[];
  targetsLoading: boolean;
  targetsError: string | null;
  disabled?: boolean;
  onTargetId: (value: string) => void;
  onSeverity: (value: string) => void;
  onStatus: (value: string) => void;
};

export function FindingReviewFilters({
  targetId,
  severity,
  status,
  targets,
  targetsLoading,
  targetsError,
  disabled,
  onTargetId,
  onSeverity,
  onStatus,
}: Props) {
  return (
    <div className="flex flex-wrap gap-3">
      <label className="text-sm text-zinc-700">
        <span className="mb-1 block text-zinc-500">Target</span>
        <select
          value={targetId}
          disabled={disabled || targetsLoading || Boolean(targetsError)}
          className="rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
          onChange={(event) => onTargetId(event.target.value)}
        >
          <option value="">All targets</option>
          {targets.map((target) => (
            <option key={target.id} value={target.id}>
              {target.domain}
            </option>
          ))}
        </select>
        {targetsLoading ? (
          <span className="mt-1 block text-xs text-zinc-500">Loading targets…</span>
        ) : null}
        {targetsError ? (
          <span className="mt-1 block text-xs text-amber-800">{targetsError}</span>
        ) : null}
      </label>
      <label className="text-sm text-zinc-700">
        <span className="mb-1 block text-zinc-500">Severity</span>
        <select
          value={severity}
          disabled={disabled}
          className="rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
          onChange={(event) => onSeverity(event.target.value)}
        >
          {SEVERITY_OPTIONS.map(([value, label]) => (
            <option key={value || "all"} value={value}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label className="text-sm text-zinc-700">
        <span className="mb-1 block text-zinc-500">Finding status</span>
        <select
          value={status}
          disabled={disabled}
          className="rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
          onChange={(event) => onStatus(event.target.value)}
        >
          {STATUS_OPTIONS.map(([value, label]) => (
            <option key={value || "all"} value={value}>
              {label}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}
