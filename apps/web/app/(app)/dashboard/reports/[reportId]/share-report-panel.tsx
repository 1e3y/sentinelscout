"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  createAssessmentReportShare,
  fetchAssessmentReportShares,
  revokeAssessmentReportShare,
} from "@/lib/api";
import type { ReportShareListItem } from "@/lib/shared-report";

type Props = {
  reportId: string;
};

const EXPIRY_OPTIONS = [
  { value: "24h" as const, label: "24 hours" },
  { value: "7d" as const, label: "7 days" },
  { value: "30d" as const, label: "30 days" },
];

export function ShareReportPanel({ reportId }: Props) {
  const { getToken } = useAuth();
  const [expiresIn, setExpiresIn] = useState<"24h" | "7d" | "30d">("7d");
  const [createdUrl, setCreatedUrl] = useState<string | null>(null);
  const [shares, setShares] = useState<ReportShareListItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [copied, setCopied] = useState(false);

  function refresh() {
    startTransition(async () => {
      try {
        const token = await getToken();
        if (!token) return;
        setShares(await fetchAssessmentReportShares(token, reportId));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load shares");
      }
    });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportId]);

  async function onCreate() {
    setError(null);
    setCopied(false);
    startTransition(async () => {
      try {
        const token = await getToken();
        if (!token) throw new Error("Missing session token");
        const created = await createAssessmentReportShare(token, reportId, expiresIn);
        setCreatedUrl(created.share_url);
        const next = await fetchAssessmentReportShares(token, reportId);
        setShares(next);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to create share");
      }
    });
  }

  async function onCopy() {
    if (!createdUrl) return;
    await navigator.clipboard.writeText(createdUrl);
    setCopied(true);
  }

  async function onRevoke(shareId: string) {
    setError(null);
    startTransition(async () => {
      try {
        const token = await getToken();
        if (!token) throw new Error("Missing session token");
        await revokeAssessmentReportShare(token, shareId);
        if (createdUrl?.includes(shareId)) {
          setCreatedUrl(null);
        }
        setShares(await fetchAssessmentReportShares(token, reportId));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to revoke share");
      }
    });
  }

  return (
    <section className="space-y-3 rounded-md border border-zinc-200 p-4">
      <h2 className="text-sm font-medium">Share report</h2>
      <p className="text-xs text-zinc-600">
        Creates a read-only external link for this exact report version. The full
        link is shown once and cannot be recovered. Anyone with the link can view
        or download the report until it expires or you revoke it. Copies already
        opened, copied, or downloaded cannot be recalled.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs text-zinc-600">
          Expires
          <select
            className="ml-2 rounded-md border border-zinc-300 px-2 py-1 text-sm"
            value={expiresIn}
            onChange={(event) =>
              setExpiresIn(event.target.value as "24h" | "7d" | "30d")
            }
          >
            {EXPIRY_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          disabled={pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={() => {
            void onCreate();
          }}
        >
          {pending ? "Working…" : "Create link"}
        </button>
      </div>
      {createdUrl ? (
        <div className="space-y-2 rounded-md bg-zinc-50 p-3">
          <p className="text-xs text-zinc-600">
            Copy this link now. If it is lost, revoke it and create a new share.
          </p>
          <p className="break-all font-mono text-xs text-zinc-800">{createdUrl}</p>
          <button
            type="button"
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
            onClick={() => {
              void onCopy();
            }}
          >
            {copied ? "Copied" : "Copy link"}
          </button>
        </div>
      ) : null}
      {error ? <p className="text-xs text-red-700">{error}</p> : null}
      <ul className="space-y-1 text-xs text-zinc-700">
        {shares.map((share) => (
          <li
            key={share.id}
            className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-100 pt-2"
          >
            <span>
              {share.status} · expires {new Date(share.expires_at).toLocaleString()}
            </span>
            {share.status === "active" ? (
              <button
                type="button"
                disabled={pending}
                className="rounded-md border border-zinc-300 px-2 py-1 disabled:opacity-50"
                onClick={() => {
                  void onRevoke(share.id);
                }}
              >
                Revoke
              </button>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}
