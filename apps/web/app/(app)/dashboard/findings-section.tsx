"use client";

import { useEffect, useState } from "react";
import { FindingFollowUpReviewPanel } from "./finding-follow-up-review-panel";
import { FindingOwnershipReviewPanel } from "./finding-ownership-review-panel";
import { FindingsInboxPanel } from "./findings-inbox-panel";
import { FindingsPanel } from "./findings-panel";

type Props = {
  enabled: boolean;
  isAdmin: boolean;
  organizationId: string | null;
};

/**
 * Owns the finding selection shared between the organization-scoped inbox,
 * admin ownership review, and the single-finding detail panel (M33).
 */
export function FindingsSection({ enabled, isAdmin, organizationId }: Props) {
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    // Organization selection is external context; clear only after it changes.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSelectedFindingId(null);
  }, [organizationId]);

  return (
    <>
      <FindingsInboxPanel
        enabled={enabled}
        selectedFindingId={selectedFindingId}
        onSelect={setSelectedFindingId}
        reloadToken={reloadToken}
      />
      {isAdmin ? (
        <>
          <FindingOwnershipReviewPanel
            enabled={enabled}
            organizationId={organizationId}
            selectedFindingId={selectedFindingId}
            onOpenFinding={setSelectedFindingId}
          />
          <FindingFollowUpReviewPanel
            enabled={enabled}
            organizationId={organizationId}
            selectedFindingId={selectedFindingId}
            onOpenFinding={setSelectedFindingId}
          />
        </>
      ) : null}
      <FindingsPanel
        key={`${organizationId ?? "no-org"}:${selectedFindingId ?? "no-finding"}`}
        organizationId={organizationId}
        findingId={selectedFindingId}
        onFindingChanged={() => setReloadToken((value) => value + 1)}
      />
    </>
  );
}
