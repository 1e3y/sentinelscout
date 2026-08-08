import Link from "next/link";

export default function CancelPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-zinc-50 px-4">
      <div className="w-full max-w-lg rounded-2xl border border-zinc-200 bg-white p-8 text-center shadow-sm">
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          Checkout canceled
        </h1>
        <p className="mt-3 text-zinc-600">
          You were not charged. Return to the dashboard whenever you are ready.
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
