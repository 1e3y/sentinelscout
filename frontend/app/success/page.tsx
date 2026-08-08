"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

export default function SuccessPage() {
  const [domain, setDomain] = useState("your domain");

  useEffect(() => {
    const checkoutDomain = sessionStorage.getItem(
      "sentinel-scout-checkout-domain",
    );
    if (checkoutDomain) {
      setDomain(checkoutDomain);
      sessionStorage.removeItem("sentinel-scout-checkout-domain");
    }
  }, []);

  return (
    <main className="flex min-h-screen items-center justify-center bg-zinc-50 px-4">
      <div className="w-full max-w-lg rounded-2xl border border-zinc-200 bg-white p-8 text-center shadow-sm">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 text-2xl text-emerald-700">
          ✓
        </div>
        <h1 className="mt-6 text-2xl font-semibold tracking-tight text-zinc-900">
          Payment successful!
        </h1>
        <p className="mt-3 text-zinc-600">
          Your scan for <span className="font-medium text-zinc-900">{domain}</span>{" "}
          is processing.
        </p>
        <Link
          href="/scan"
          className="mt-8 inline-flex rounded-lg bg-zinc-900 px-5 py-3 text-sm font-medium text-white transition hover:bg-zinc-800"
        >
          Return to dashboard
        </Link>
      </div>
    </main>
  );
}
