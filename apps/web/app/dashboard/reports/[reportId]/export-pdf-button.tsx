"use client";

import { useAuth } from "@clerk/nextjs";
import { useState } from "react";
import { exportAssessmentReportPdf } from "@/lib/api";

type Props = {
  reportId: string;
};

export function ExportPdfButton({ reportId }: Props) {
  const { getToken } = useAuth();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onExport() {
    setPending(true);
    setError(null);
    try {
      const token = await getToken();
      if (!token) {
        throw new Error("Missing session token");
      }
      const { blob, filename } = await exportAssessmentReportPdf(token, reportId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export PDF");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <button
        type="button"
        disabled={pending}
        className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
        onClick={() => {
          void onExport();
        }}
      >
        {pending ? "Exporting PDF…" : "Export PDF"}
      </button>
      {error ? <p className="max-w-xs text-right text-xs text-red-700">{error}</p> : null}
    </div>
  );
}
