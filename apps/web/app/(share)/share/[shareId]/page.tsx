import { SharedReportClient } from "./shared-report-client";

export const dynamic = "force-dynamic";
export const fetchCache = "force-no-store";

type Props = {
  params: Promise<{ shareId: string }>;
};

export default async function SharedReportPage({ params }: Props) {
  const { shareId } = await params;
  return <SharedReportClient shareId={shareId} />;
}
