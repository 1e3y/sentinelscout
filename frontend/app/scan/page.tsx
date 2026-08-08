import { UserButton } from "@clerk/nextjs";
import Link from "next/link";

import ScanDashboard from "@/components/ScanDashboard";

export default function ScanPage() {
  return (
    <div className="min-h-screen bg-zinc-50">
      <nav className="border-b border-zinc-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-4 sm:px-6">
          <Link
            href="/scan"
            className="text-sm font-semibold tracking-tight text-zinc-900"
          >
            SentinelScout
          </Link>
          <UserButton />
        </div>
      </nav>

      <main className="mx-auto w-full max-w-5xl px-4 py-16 sm:px-6">
        <ScanDashboard />
      </main>
    </div>
  );
}
