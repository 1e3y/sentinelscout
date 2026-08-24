import type { SharedReportPublic } from "@/lib/shared-report";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

function filenameFromContentDisposition(header: string | null): string {
  const fallback = "assessment-report.pdf";
  if (!header) return fallback;
  const match = /filename="([^"]+)"/i.exec(header);
  const name = match?.[1] ?? "";
  if (!/^[a-z0-9][a-z0-9._-]*\.pdf$/.test(name)) return fallback;
  return name;
}

export async function resolveSharedReport(
  shareId: string,
  secret: string,
): Promise<SharedReportPublic> {
  const response = await fetch(
    `${API_BASE_URL}/v1/shared-reports/${shareId}/resolve`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ secret }),
      cache: "no-store",
    },
  );
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error("Shared report not found");
    }
    if (response.status === 503) {
      throw new Error("Shared report is unavailable");
    }
    throw new Error("Shared report not found");
  }
  return (await response.json()) as SharedReportPublic;
}

export async function exportSharedReportPdf(
  shareId: string,
  secret: string,
): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch(
    `${API_BASE_URL}/v1/shared-reports/${shareId}/pdf`,
    {
      method: "POST",
      headers: {
        Accept: "application/pdf",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ secret }),
      cache: "no-store",
    },
  );
  if (!response.ok) {
    if (response.status === 409) {
      throw new Error(
        "This report contains characters that the PDF exporter cannot render yet.",
      );
    }
    if (response.status === 503) {
      throw new Error("PDF export is unavailable");
    }
    throw new Error("Shared report not found");
  }
  return {
    blob: await response.blob(),
    filename: filenameFromContentDisposition(
      response.headers.get("Content-Disposition"),
    ),
  };
}
