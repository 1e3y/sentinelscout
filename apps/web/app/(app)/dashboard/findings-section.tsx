"use client";

import { useState } from "react";
import { FindingOwnershipReviewPanel } from "./finding-ownership-review-panel";
import { FindingsInboxPanel } from "./findings-inbox-panel";
import { FindingsPanel } from "./findings-panel";

type Props = {
  enabled: boolean;
  isAdmin: boolean;
};

/**
 * Owns the finding selection shared between the organization-scoped inbox,
 * admin ownership review, and the single-finding detail panel (M33).
 */
export function FindingsSection({ enabled, isAdmin }: Props) {
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  return (
    <>
      <FindingsInboxPanel
        enabled={enabled}
        selectedFindingId={selectedFindingId}
        onSelect={setSelectedFindingId}
        reloadToken={reloadToken}
      />
      {isAdmin ? (
        <FindingOwnershipReviewPanel
          enabled={enabled}
          selectedFindingId={selectedFindingId}
          onOpenFinding={setSelectedFindingId}
        />
      ) : null}
      <FindingsPanel
        findingId={selectedFindingId}
        onFindingChanged={() => setReloadToken((value) => value + 1)}
      />
    </>
  );
}
