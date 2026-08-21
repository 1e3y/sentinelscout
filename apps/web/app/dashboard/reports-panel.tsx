"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useState, useTransition } from "react";
import {
  fetchAssessmentReports,
  type AssessmentReportSummaryResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

export function ReportsPanel({ enabled }: Props) {
  const { getToken } = useAuth();
  const [reports, setReports] = useState<AssessmentReportSummaryResponse[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function refresh() {
    if (!enabled) return;
    startTransition(async () => {
      setError(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        setReports(await fetchAssessmentReports(token));
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load assessment reports",
        );
      }
    });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-medium">Assessment reports</h2>
        <button
          type="button"
          disabled={!enabled || pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={refresh}
        >
          Refresh
        </button>
      </div>
      <p className="text-xs text-zinc-500">
        Each report is an immutable snapshot of one operation. Generate a report from
        an operation in the Operations panel.
      </p>

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
          {error}
        </p>
      ) : null}

      {reports.length === 0 ? (
        <p className="text-sm text-zinc-600">No assessment reports yet.</p>
      ) : (
        <ul className="space-y-2">
          {reports.map((report) => (
            <li
              key={report.id}
              className="space-y-1 rounded-md border border-zinc-200 p-3 text-sm"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{report.target_domain}</span>
                <span className="rounded border border-zinc-300 px-2 py-0.5 text-xs text-zinc-700">
                  v{report.report_version}
                </span>
                <span
                  className={`rounded border px-2 py-0.5 text-xs ${
                    report.assessment_completeness === "incomplete"
                      ? "border-amber-400 bg-amber-50 text-amber-900"
                      : "border-zinc-300 text-zinc-700"
                  }`}
                >
                  {report.headline_label}
                </span>
              </div>
              <p className="text-xs text-zinc-500">
                {formatTime(report.generated_at)} · operation{" "}
                {report.operation_status_at_generation} · {report.findings_open} open
                of {report.findings_total} findings ·{" "}
                {report.coverage_limitation_count} coverage limitation(s)
              </p>
              <Link
                href={`/dashboard/reports/${report.id}`}
                className="inline-block underline underline-offset-2"
              >
                View report
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
