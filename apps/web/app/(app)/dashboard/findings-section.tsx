"use client";

import { useState } from "react";
import { FindingsInboxPanel } from "./findings-inbox-panel";
import { FindingsPanel } from "./findings-panel";

type Props = {
  enabled: boolean;
};

/**
 * Owns the finding selection shared between the organization-scoped inbox and
 * the single-finding detail panel. Exactly one finding collection is rendered.
 */
export function FindingsSection({ enabled }: Props) {
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
      <FindingsPanel
        findingId={selectedFindingId}
        onFindingChanged={() => setReloadToken((value) => value + 1)}
      />
    </>
  );
}
