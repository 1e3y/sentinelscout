"use client";

import { useUser } from "@clerk/nextjs";
import { FormEvent, useState } from "react";

const STRIPE_PRICE_ID = process.env.NEXT_PUBLIC_STRIPE_PRICE_ID;

type SubdomainResult = {
  url?: string;
  subdomain?: string;
  status_code?: number | null;
  title?: string;
  category?: string;
  risk_level?: string;
  notes?: string;
};

function riskBadgeClass(riskLevel?: string): string {
  const level = (riskLevel || "").toLowerCase();
  if (level === "high") {
    return "bg-red-50 text-red-700 ring-red-200";
  }
  if (level === "medium") {
    return "bg-amber-50 text-amber-700 ring-amber-200";
  }
  if (level === "low") {
    return "bg-emerald-50 text-emerald-700 ring-emerald-200";
  }
  return "bg-zinc-50 text-zinc-600 ring-zinc-200";
}

export default function ScanDashboard() {
  const { user } = useUser();
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [results, setResults] = useState<any>(null);
  const [scannedDomain, setScannedDomain] = useState<string | null>(null);

  async function handleScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const trimmedDomain = domain.trim();
    if (!trimmedDomain) {
      setError("Please enter a domain.");
      return;
    }

    setLoading(true);
    setError(null);
    setDownloadError(null);
    setResults(null);
    setScannedDomain(null);

    try {
      const response = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain: trimmedDomain }),
      });

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        const message =
          typeof data?.detail === "string"
            ? data.detail
            : "Scan failed. Please try again.";
        throw new Error(message);
      }

      setResults(data);
      setScannedDomain(
        typeof data?.domain === "string" ? data.domain : trimmedDomain,
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to reach the scan service.",
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleDownloadReport() {
    if (!scannedDomain) {
      return;
    }

    setDownloadingPdf(true);
    setDownloadError(null);

    try {
      const response = await fetch("http://localhost:8000/report", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain: scannedDomain }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => null);
        const message =
          typeof data?.detail === "string"
            ? data.detail
            : "Failed to generate PDF report.";
        throw new Error(message);
      }

      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition");
      const filenameMatch = disposition?.match(/filename="?([^";\n]+)"?/);
      const filename =
        filenameMatch?.[1] ??
        `sentinel-scout-${scannedDomain}-${new Date().toISOString().slice(0, 10)}.pdf`;

      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setDownloadError(
        err instanceof Error
          ? err.message
          : "Unable to download the PDF report.",
      );
    } finally {
      setDownloadingPdf(false);
    }
  }

  async function handleBuyScan() {
    const priceId = process.env.NEXT_PUBLIC_STRIPE_PRICE_ID;
    const trimmedDomain = domain.trim();

    if (!trimmedDomain) {
      setError("Please enter a domain before purchasing a scan.");
      return;
    }

    if (!priceId) {
      setError("Stripe price ID is not configured in NEXT_PUBLIC_STRIPE_PRICE_ID.");
      return;
    }

    setCheckoutLoading(true);
    setError(null);

    try {
      const response = await fetch(
        "http://localhost:8000/create-checkout-session",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            price_id: priceId,
            domain: trimmedDomain,
            user_email: user?.primaryEmailAddress?.emailAddress || null,
          }),
        },
      );

      const data = await response.json().catch(() => null);

      if (!response.ok || typeof data?.url !== "string") {
        const message =
          typeof data?.detail === "string"
            ? data.detail
            : "Unable to start Stripe Checkout.";
        throw new Error(message);
      }

      sessionStorage.setItem("sentinel-scout-checkout-domain", trimmedDomain);
      window.location.assign(data.url);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to start Stripe Checkout.",
      );
      setCheckoutLoading(false);
    }
  }

  const tableRows: SubdomainResult[] = Array.isArray(results)
    ? results
    : Array.isArray(results?.data)
      ? results.data
      : Array.isArray(results?.subdomains)
        ? results.subdomains
        : [];

  return (
    <>
      <header className="mb-10 text-center">
        <h1 className="text-3xl font-semibold tracking-tight text-zinc-900">
          Scan Dashboard
        </h1>
        <p className="mt-2 text-sm text-zinc-500">
          Subdomain discovery and AI-powered risk analysis
        </p>
      </header>

      <form
        onSubmit={handleScan}
        className="mx-auto flex max-w-2xl flex-col gap-3 sm:flex-row"
      >
        <input
          type="text"
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
          placeholder="Enter domain (e.g., yahoo.com)"
          disabled={loading}
          className="flex-1 rounded-lg border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-900 shadow-sm outline-none transition focus:border-zinc-400 focus:ring-2 focus:ring-zinc-200 disabled:cursor-not-allowed disabled:opacity-60"
        />
        <button
          type="submit"
          disabled={loading}
          className="rounded-lg bg-zinc-900 px-6 py-3 text-sm font-medium text-white transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? "Scanning..." : "Scan"}
        </button>
        <button
          type="button"
          onClick={handleBuyScan}
          disabled={loading || checkoutLoading}
          className="rounded-lg border border-zinc-900 bg-white px-6 py-3 text-sm font-medium text-zinc-900 transition hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {checkoutLoading ? "Redirecting..." : "Buy Scan ($299)"}
        </button>
      </form>

      {loading && (
        <div className="mt-12 flex flex-col items-center gap-3">
          <div
            className="h-8 w-8 animate-spin rounded-full border-2 border-zinc-200 border-t-zinc-900"
            aria-hidden="true"
          />
          <p className="text-sm text-zinc-500">
            Scanning subdomains and running analysis...
          </p>
        </div>
      )}

      {error && (
        <div className="mx-auto mt-8 max-w-xl rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {results && !loading && (
        <div className="mt-10 space-y-6">
          <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
            <div className="text-sm text-zinc-500">
              Report ready for{" "}
              <span className="font-medium text-zinc-800">{scannedDomain}</span>
            </div>
            <button
              type="button"
              onClick={handleDownloadReport}
              disabled={downloadingPdf}
              className="inline-flex items-center gap-2 rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-900 shadow-sm transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {downloadingPdf && (
                <span
                  className="h-4 w-4 animate-spin rounded-full border-2 border-zinc-200 border-t-zinc-900"
                  aria-hidden="true"
                />
              )}
              {downloadingPdf ? "Generating PDF..." : "Download PDF Report"}
            </button>
          </div>

          {downloadError && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {downloadError}
            </div>
          )}

          {results.summary && (
            <div className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
              <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">
                Summary
              </h2>
              <p className="text-sm leading-relaxed text-zinc-700">
                {results.summary}
              </p>
            </div>
          )}

          <div className="overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-sm">
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-zinc-200 bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
                    <th className="px-4 py-3 font-medium">Subdomain</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Category</th>
                    <th className="px-4 py-3 font-medium">Risk Level</th>
                    <th className="px-4 py-3 font-medium">Notes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200">
                  {tableRows.length > 0 ? (
                    tableRows.map((item, index) => (
                      <tr key={index} className="hover:bg-zinc-50/50">
                        <td className="px-4 py-3 font-mono text-xs text-zinc-800">
                          {item.subdomain || item.url || "N/A"}
                        </td>
                        <td className="px-4 py-3 text-zinc-600">
                          {item.status_code ?? "—"}
                        </td>
                        <td className="px-4 py-3 text-zinc-600">
                          {item.category || "General"}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${riskBadgeClass(
                              item.risk_level || "Low",
                            )}`}
                          >
                            {item.risk_level || "Low"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-zinc-500">
                          {item.notes || "No notes"}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td
                        colSpan={5}
                        className="px-4 py-8 text-center text-zinc-500"
                      >
                        No results found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
