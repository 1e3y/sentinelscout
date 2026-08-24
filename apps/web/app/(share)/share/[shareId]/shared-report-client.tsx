"use client";

import { useEffect, useState } from "react";
import {
  exportSharedReportPdf,
  resolveSharedReport,
} from "@/lib/shared-report-api";
import type { SharedReportPublic } from "@/lib/shared-report";
import { SharedReportView } from "./shared-report-view";

const SHARE_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

type Props = {
  shareId: string;
};

export function SharedReportClient({ shareId }: Props) {
  const [report, setReport] = useState<SharedReportPublic | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingPdf, setPendingPdf] = useState(false);

  useEffect(() => {
    const raw = window.location.hash.replace(/^#/, "");
    window.history.replaceState(null, "", `/share/${shareId}`);
    let cancelled = false;
    void (async () => {
      if (!SHARE_SECRET_PATTERN.test(raw)) {
        if (cancelled) return;
        setSecret(null);
        setError("Shared report not found");
        return;
      }
      try {
        const payload = await resolveSharedReport(shareId, raw);
        if (cancelled) return;
        setSecret(raw);
        setReport(payload);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        setSecret(null);
        setReport(null);
        setError(err instanceof Error ? err.message : "Shared report not found");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [shareId]);

  async function onExport() {
    if (!secret) return;
    setPendingPdf(true);
    setError(null);
    try {
      const { blob, filename } = await exportSharedReportPdf(shareId, secret);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export PDF");
    } finally {
      setPendingPdf(false);
    }
  }

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-6 px-6 py-10">
      <div className="flex items-center justify-between gap-4">
        <p className="text-sm text-zinc-600">Shared assessment report</p>
        {report && secret ? (
          <button
            type="button"
            disabled={pendingPdf}
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
            onClick={() => {
              void onExport();
            }}
          >
            {pendingPdf ? "Exporting PDF…" : "Export PDF"}
          </button>
        ) : null}
      </div>
      {error ? (
        <section className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          {error}
        </section>
      ) : null}
      {report ? <SharedReportView report={report} /> : null}
    </div>
  );
}
