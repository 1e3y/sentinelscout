"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  createTarget,
  fetchTargetScope,
  fetchTargets,
  revokeTarget,
  startTargetVerification,
  updateTargetScope,
  verifyTarget,
  type TargetResponse,
  type TargetScopeResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
  isAdmin: boolean;
};

export function TargetsPanel({ enabled, isAdmin }: Props) {
  const { getToken } = useAuth();
  const [targets, setTargets] = useState<TargetResponse[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scope, setScope] = useState<TargetScopeResponse | null>(null);
  const [domainInput, setDomainInput] = useState("");
  const [exclusionInput, setExclusionInput] = useState("");
  const [includeSubdomains, setIncludeSubdomains] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const selected = targets.find((t) => t.id === selectedId) ?? null;
  const visibleScope = scope?.target_id === selectedId ? scope : null;

  async function withToken<T>(fn: (token: string) => Promise<T>): Promise<T | null> {
    const token = await getToken();
    if (!token) {
      setError("Missing session token");
      return null;
    }
    return fn(token);
  }

  function refresh() {
    if (!enabled) return;
    startTransition(async () => {
      setError(null);
      try {
        const list = await withToken(fetchTargets);
        if (!list) return;
        setTargets(list);
        setSelectedId((current) => {
          if (current && list.some((t) => t.id === current)) return current;
          return list[0]?.id ?? null;
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load targets");
      }
    });
  }

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    startTransition(async () => {
      setError(null);
      try {
        const token = await getToken();
        if (!token || cancelled) return;
        const list = await fetchTargets(token);
        if (cancelled) return;
        setTargets(list);
        setSelectedId((current) => {
          if (current && list.some((t) => t.id === current)) return current;
          return list[0]?.id ?? null;
        });
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load targets");
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, [enabled, getToken]);

  useEffect(() => {
    if (!selectedId || !enabled) return;
    let cancelled = false;
    startTransition(async () => {
      try {
        const token = await getToken();
        if (!token || cancelled) return;
        const next = await fetchTargetScope(token, selectedId);
        if (cancelled) return;
        setScope(next);
        setIncludeSubdomains(next.include_subdomains);
        setExclusionInput(next.exclusions.join("\n"));
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load scope");
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, [selectedId, enabled, getToken]);

  if (!enabled) {
    return (
      <section className="space-y-2">
        <h2 className="text-lg font-medium">Targets</h2>
        <p className="text-sm text-zinc-600">
          Select an active organization to manage authorized targets.
        </p>
      </section>
    );
  }

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-medium">Targets</h2>
        <button
          type="button"
          onClick={refresh}
          disabled={pending}
          className="text-sm text-zinc-600 underline"
        >
          Refresh
        </button>
      </div>

      {isAdmin ? (
      <form
        className="flex flex-col gap-2 sm:flex-row"
        onSubmit={(event) => {
          event.preventDefault();
          startTransition(async () => {
            setError(null);
            setMessage(null);
            try {
              const created = await withToken((token) =>
                createTarget(token, domainInput.trim()),
              );
              if (!created) return;
              setDomainInput("");
              setMessage(`Added ${created.domain}`);
              const list = await withToken(fetchTargets);
              if (list) {
                setTargets(list);
                setSelectedId(created.id);
              }
            } catch (err) {
              setError(err instanceof Error ? err.message : "Failed to add target");
            }
          });
        }}
      >
        <input
          value={domainInput}
          onChange={(event) => setDomainInput(event.target.value)}
          placeholder="example.com"
          className="min-w-0 flex-1 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm"
          required
        />
        <button
          type="submit"
          disabled={pending}
          className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          Add target
        </button>
      </form>
      ) : (
        <p className="text-sm text-zinc-600">
          Organization admins add, verify, revoke, and change the authorized
          scope of targets.
        </p>
      )}

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
          {error}
        </p>
      ) : null}
      {message ? (
        <p className="rounded-md border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-700">
          {message}
        </p>
      ) : null}

      {targets.length === 0 ? (
        <p className="text-sm text-zinc-600">No targets registered yet.</p>
      ) : (
        <ul className="divide-y divide-zinc-200 rounded-md border border-zinc-200 bg-white">
          {targets.map((target) => (
            <li key={target.id}>
              <button
                type="button"
                onClick={() => setSelectedId(target.id)}
                className={`flex w-full items-center justify-between px-4 py-3 text-left text-sm ${
                  selectedId === target.id ? "bg-zinc-100" : ""
                }`}
              >
                <span className="font-medium">{target.domain}</span>
                <span className="font-mono text-xs text-zinc-500">{target.status}</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {selected ? (
        <div className="space-y-4 rounded-md border border-zinc-200 bg-white p-4">
          <div className="space-y-1">
            <h3 className="font-medium">{selected.domain}</h3>
            <p className="text-sm text-zinc-600">
              Status: <span className="font-mono text-xs">{selected.status}</span>
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            {isAdmin ? (
              <>
            <button
              type="button"
              disabled={pending || selected.status === "revoked"}
              className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
              onClick={() => {
                startTransition(async () => {
                  setError(null);
                  setMessage(null);
                  try {
                    const updated = await withToken((token) =>
                      startTargetVerification(token, selected.id),
                    );
                    if (!updated) return;
                    setTargets((prev) =>
                      prev.map((t) => (t.id === updated.id ? updated : t)),
                    );
                    setMessage("Verification challenge created. Add the TXT record below.");
                  } catch (err) {
                    setError(
                      err instanceof Error ? err.message : "Failed to start verification",
                    );
                  }
                });
              }}
            >
              Get DNS instructions
            </button>
            <button
              type="button"
              disabled={pending || selected.status === "revoked"}
              className="rounded-md bg-zinc-900 px-3 py-1.5 text-sm text-white disabled:opacity-50"
              onClick={() => {
                startTransition(async () => {
                  setError(null);
                  setMessage(null);
                  try {
                    const result = await withToken((token) =>
                      verifyTarget(token, selected.id),
                    );
                    if (!result) return;
                    setMessage(result.detail);
                    const list = await withToken(fetchTargets);
                    if (list) setTargets(list);
                  } catch (err) {
                    setError(err instanceof Error ? err.message : "Verification failed");
                  }
                });
              }}
            >
              Verify domain
            </button>
            <button
              type="button"
              disabled={pending || selected.status === "revoked"}
              className="rounded-md border border-red-300 px-3 py-1.5 text-sm text-red-700 disabled:opacity-50"
              onClick={() => {
                startTransition(async () => {
                  setError(null);
                  setMessage(null);
                  try {
                    const updated = await withToken((token) =>
                      revokeTarget(token, selected.id),
                    );
                    if (!updated) return;
                    setTargets((prev) =>
                      prev.map((t) => (t.id === updated.id ? updated : t)),
                    );
                    setMessage(`${updated.domain} revoked`);
                  } catch (err) {
                    setError(err instanceof Error ? err.message : "Failed to revoke target");
                  }
                });
              }}
            >
              Revoke target
            </button>
              </>
            ) : null}
          </div>

          {selected.status === "revoked" ? (
            <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
              This target is revoked. Historical records remain, but new operations
              cannot be created against it.
            </p>
          ) : null}

          {selected.authorization ? (
            <div className="space-y-2 text-sm">
              <h4 className="font-medium">DNS TXT verification</h4>
              <p className="text-zinc-600">
                Create this TXT record, then click Verify domain. Verification is
                performed by the API.
              </p>
              <dl className="grid gap-2 rounded-md bg-zinc-50 p-3 font-mono text-xs">
                <div>
                  <dt className="text-zinc-500">Name</dt>
                  <dd className="break-all">{selected.authorization.txt_name}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Value</dt>
                  <dd className="break-all">{selected.authorization.txt_value}</dd>
                </div>
              </dl>
            </div>
          ) : isAdmin ? (
            <p className="text-sm text-zinc-600">
              Click “Get DNS instructions” to generate a verification challenge.
            </p>
          ) : (
            <p className="text-sm text-zinc-600">
              DNS verification is managed by organization admins.
            </p>
          )}

          <div className="space-y-3 border-t border-zinc-100 pt-4">
            <h4 className="font-medium">Scope</h4>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={includeSubdomains}
                disabled={!isAdmin}
                onChange={(event) => setIncludeSubdomains(event.target.checked)}
              />
              Include subdomains
            </label>
            <label className="block space-y-1 text-sm">
              <span className="text-zinc-600">Exclusions (one domain per line)</span>
              <textarea
                value={exclusionInput}
                onChange={(event) => setExclusionInput(event.target.value)}
                rows={4}
                disabled={!isAdmin}
                className="w-full rounded-md border border-zinc-300 px-3 py-2 font-mono text-xs"
                placeholder={"dev.example.com\nstaging.example.com"}
              />
            </label>
            {isAdmin ? (
            <button
              type="button"
              disabled={pending}
              className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
              onClick={() => {
                startTransition(async () => {
                  setError(null);
                  setMessage(null);
                  const exclusions = exclusionInput
                    .split("\n")
                    .map((line) => line.trim())
                    .filter(Boolean);
                  try {
                    const next = await withToken((token) =>
                      updateTargetScope(token, selected.id, {
                        include_subdomains: includeSubdomains,
                        exclusions,
                      }),
                    );
                    if (!next) return;
                    setScope(next);
                    setMessage("Scope saved");
                  } catch (err) {
                    setError(err instanceof Error ? err.message : "Failed to save scope");
                  }
                });
              }}
            >
              Save scope
            </button>
            ) : (
              <p className="text-xs text-zinc-500">
                Scope is read-only for organization members.
              </p>
            )}
            {visibleScope ? (
              <p className="text-xs text-zinc-500">
                Root: {visibleScope.root_domain}. Current exclusions:{" "}
                {visibleScope.exclusions.length
                  ? visibleScope.exclusions.join(", ")
                  : "none"}
                .
              </p>
            ) : null}
          </div>
        </div>
      ) : null}
    </section>
  );
}
