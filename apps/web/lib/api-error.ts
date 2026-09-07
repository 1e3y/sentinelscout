/** Extract the public API error message without exposing provider bodies. */

export type ParsedApiError = {
  status: number | null;
  message: string;
};

export function parseApiError(err: unknown, fallback: string): ParsedApiError {
  if (!(err instanceof Error)) {
    return { status: null, message: fallback };
  }
  const matched = err.message.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  if (!matched) {
    return { status: null, message: err.message || fallback };
  }
  const status = Number(matched[1]);
  const raw = matched[2] ?? "";
  try {
    const body = JSON.parse(raw) as { error?: { message?: unknown } };
    if (typeof body.error?.message === "string" && body.error.message.trim()) {
      return { status, message: body.error.message };
    }
  } catch {
    // Keep the fallback rather than dumping a raw provider-shaped body.
  }
  return { status, message: fallback };
}
