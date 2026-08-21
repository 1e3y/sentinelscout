import { auth } from "@clerk/nextjs/server";
import Link from "next/link";
import { redirect } from "next/navigation";
import { fetchAssessmentReport } from "@/lib/api";
import { AssessmentReportView } from "./report-view";

type Props = {
  params: Promise<{ reportId: string }>;
};

export default async function AssessmentReportPage({ params }: Props) {
  const { reportId } = await params;
  const session = await auth();
  if (!session.userId) {
    redirect("/sign-in");
  }

  const token = await session.getToken();
  if (!token) {
    redirect("/sign-in");
  }

  let report = null;
  let error: string | null = null;
  try {
    report = await fetchAssessmentReport(token, reportId);
  } catch (err) {
    error = err instanceof Error ? err.message : "Failed to load assessment report";
  }

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-6 px-6 py-10">
      <div className="report-chrome flex items-center justify-between gap-4">
        <Link
          href="/dashboard"
          className="text-sm text-zinc-600 underline underline-offset-2"
        >
          Back to dashboard
        </Link>
        <p className="text-xs text-zinc-500">
          Use your browser&apos;s Print / Save as PDF to export this report.
        </p>
      </div>

      {error || !report ? (
        <section className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          Could not load this assessment report. {error}
        </section>
      ) : (
        <AssessmentReportView report={report} />
      )}
    </div>
  );
}
