import {
  type FindingTimelineEvent,
  type FindingTimelineHistoryGap,
  type FindingTimelineResponse,
} from "@/lib/api";

type Props = {
  timeline: FindingTimelineResponse;
  pending: boolean;
  onLoadMore: () => void;
};

const provenanceLabels: Record<FindingTimelineEvent["provenance"], string> = {
  finding_record: "Finding record",
  human_workflow: "Human workflow",
  human_remediation: "Customer-recorded remediation",
  scout_retest: "Scout observation",
};

const gapLabels: Record<FindingTimelineHistoryGap, string> = {
  remediation_started_timestamp_unavailable:
    "The remediation-start timestamp is unavailable.",
  ready_for_retest_timestamp_unavailable:
    "The ready-for-retest timestamp is unavailable.",
  resolution_timestamp_unavailable: "The resolution timestamp is unavailable.",
  resolution_retest_link_unavailable:
    "The historical resolving-retest link is unavailable.",
  retest_completion_timestamp_unavailable:
    "A retest completion timestamp is unavailable.",
  workflow_transition_ambiguous:
    "Duplicate workflow records make a transition timestamp ambiguous.",
};

function formatTime(value: string): string {
  return new Date(value).toLocaleString();
}

function stateLabel(value: string): string {
  return value.replaceAll("_", " ");
}

function actorLabel(event: FindingTimelineEvent): string | null {
  if (!event.actor) return null;
  if (event.actor.actor_type === "worker") return "Scout worker";
  return event.actor.display_name
    ? `By ${event.actor.display_name}`
    : "By an organization member";
}

function EventDetails({ event }: { event: FindingTimelineEvent }) {
  switch (event.event_type) {
    case "SUPPORTED_FINDING_PROMOTED":
      return (
        <p className="text-xs text-zinc-600">
          A supported candidate became a Finding.
        </p>
      );
    case "REMEDIATION_STARTED":
    case "READY_FOR_RETEST":
      return (
        <p className="text-xs text-zinc-600">
          {stateLabel(event.details.from_status)} →{" "}
          {stateLabel(event.details.to_status)}
        </p>
      );
    case "REMEDIATION_REVISION_RECORDED":
      return (
        <div className="space-y-1">
          <p className="whitespace-pre-wrap text-sm text-zinc-800">
            {event.details.summary}
          </p>
          <p className="text-xs text-zinc-600">
            Customer-recorded work; not verification.
          </p>
        </div>
      );
    case "RETEST_QUEUED":
      return (
        <p className="text-xs text-zinc-600">
          Attempt status now: {stateLabel(event.details.status_at_read)}
        </p>
      );
    case "RETEST_COMPLETED":
      return (
        <div className="space-y-1 text-xs text-zinc-600">
          <p>{event.details.summary}</p>
          <p>
            Method: <span className="font-mono">{event.details.method}</span>
          </p>
        </div>
      );
    case "FINDING_RESOLVED":
      return <p className="text-xs text-zinc-600">{event.details.statement}</p>;
  }
}

export function FindingActivityTimeline({
  timeline,
  pending,
  onLoadMore,
}: Props) {
  return (
    <section
      className="space-y-3 border-t border-zinc-100 pt-4"
      aria-labelledby="finding-activity-heading"
    >
      <div>
        <h4
          id="finding-activity-heading"
          className="text-sm font-medium text-zinc-800"
        >
          Finding activity
        </h4>
        <p className="text-xs text-zinc-600">
          Durable Finding history. Customer-recorded work and Scout observations
          are shown separately.
        </p>
      </div>

      <dl className="grid gap-2 text-xs text-zinc-700 sm:grid-cols-2">
        <div>
          <dt className="text-zinc-500">Current Finding status</dt>
          <dd className="capitalize">{stateLabel(timeline.current_status)}</dd>
        </div>
        <div>
          <dt className="text-zinc-500">Current retest state</dt>
          <dd className="capitalize">
            {stateLabel(timeline.current_retest_state)}
          </dd>
        </div>
      </dl>

      {timeline.history_completeness === "partial" ? (
        <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          <p className="font-medium">
            Some older workflow timestamps are unavailable.
          </p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4">
            {timeline.history_gaps.map((gap) => (
              <li key={gap}>{gapLabels[gap]}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <ol className="space-y-2">
        {timeline.events.map((event) => {
          const byline = actorLabel(event);
          return (
            <li
              key={event.event_id}
              className="rounded-md border border-zinc-200 p-3"
            >
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="font-medium text-zinc-800">{event.title}</p>
                <time
                  className="text-xs text-zinc-500"
                  dateTime={event.occurred_at}
                >
                  {formatTime(event.occurred_at)}
                </time>
              </div>
              <p className="mt-1 text-xs font-medium text-zinc-600">
                {provenanceLabels[event.provenance]}
                {byline ? ` · ${byline}` : ""}
              </p>
              <div className="mt-2">
                <EventDetails event={event} />
              </div>
            </li>
          );
        })}
      </ol>

      {timeline.next_cursor ? (
        <button
          type="button"
          disabled={pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
          onClick={onLoadMore}
        >
          Load older activity
        </button>
      ) : null}
    </section>
  );
}
