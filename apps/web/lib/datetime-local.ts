/** Parse HTML datetime-local values without silent DST or year-0..99 quirks. */

export type LocalDateTimeReason = "invalid" | "nonexistent" | "ambiguous";

export type LocalDateTimeParse =
  | { ok: true; iso: string; instantMs: number }
  | { ok: false; reason: LocalDateTimeReason };

export type WallParts = {
  year: number;
  monthIndex: number;
  day: number;
  hour: number;
  minute: number;
};

export type DateTimeClock = {
  fromWall(parts: WallParts): Date;
  partsOf(instant: Date): WallParts;
  timezoneOffsetMinutes(instant: Date): number;
};

export const LOCAL_TIMEZONE_LABEL = "Times are shown in your local timezone.";
export const NONEXISTENT_LOCAL_TIME =
  "That local time does not exist in your current timezone. Choose another time.";
export const AMBIGUOUS_LOCAL_TIME =
  "That local time occurs more than once in your current timezone. Choose another time.";

const INPUT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/;
const WINDOW_MS = 48 * 60 * 60 * 1000;
const SAMPLE_MS = 15 * 60 * 1000;

export const systemClock: DateTimeClock = {
  fromWall(parts) {
    const candidate = new Date(0);
    candidate.setFullYear(parts.year, parts.monthIndex, parts.day);
    candidate.setHours(parts.hour, parts.minute, 0, 0);
    return candidate;
  },
  partsOf(instant) {
    return {
      year: instant.getFullYear(),
      monthIndex: instant.getMonth(),
      day: instant.getDate(),
      hour: instant.getHours(),
      minute: instant.getMinutes(),
    };
  },
  timezoneOffsetMinutes(instant) {
    return instant.getTimezoneOffset();
  },
};

function daysInMonth(year: number, month: number): number {
  const probe = new Date(0);
  probe.setFullYear(year, month, 0);
  return probe.getDate();
}

function pad2(value: number): string {
  return String(value).padStart(2, "0");
}

export function parseLocalDateTimeInput(
  raw: string,
  clock: DateTimeClock = systemClock,
): LocalDateTimeParse {
  if (typeof raw !== "string" || raw.trim() === "") {
    return { ok: false, reason: "invalid" };
  }
  const matched = INPUT.exec(raw);
  if (!matched) return { ok: false, reason: "invalid" };
  const year = Number(matched[1]);
  const month = Number(matched[2]);
  const day = Number(matched[3]);
  const hour = Number(matched[4]);
  const minute = Number(matched[5]);
  if (year < 1) return { ok: false, reason: "invalid" };
  if (month < 1 || month > 12) return { ok: false, reason: "invalid" };
  if (hour > 23 || minute > 59) return { ok: false, reason: "invalid" };
  if (day < 1 || day > daysInMonth(year, month)) {
    return { ok: false, reason: "invalid" };
  }

  const candidate = clock.fromWall({
    year,
    monthIndex: month - 1,
    day,
    hour,
    minute,
  });
  if (Number.isNaN(candidate.getTime())) {
    return { ok: false, reason: "invalid" };
  }

  const parts = clock.partsOf(candidate);
  if (
    parts.year !== year ||
    parts.monthIndex !== month - 1 ||
    parts.day !== day ||
    parts.hour !== hour ||
    parts.minute !== minute
  ) {
    return { ok: false, reason: "nonexistent" };
  }

  const offsets = new Set<number>();
  const candidateMs = candidate.getTime();
  for (let t = candidateMs - WINDOW_MS; t <= candidateMs + WINDOW_MS; t += SAMPLE_MS) {
    offsets.add(clock.timezoneOffsetMinutes(new Date(t)));
  }
  const candidateOffset = clock.timezoneOffsetMinutes(candidate);
  offsets.add(candidateOffset);

  const matches = new Set<number>([candidateMs]);
  for (const offset of offsets) {
    if (offset === candidateOffset) continue;
    const alternative = new Date(
      candidateMs + (offset - candidateOffset) * 60_000,
    );
    const alternativeParts = clock.partsOf(alternative);
    if (
      alternative.getTime() !== candidateMs &&
      alternativeParts.year === year &&
      alternativeParts.monthIndex === month - 1 &&
      alternativeParts.day === day &&
      alternativeParts.hour === hour &&
      alternativeParts.minute === minute
    ) {
      matches.add(alternative.getTime());
    }
  }
  if (matches.size > 1) return { ok: false, reason: "ambiguous" };
  return { ok: true, iso: candidate.toISOString(), instantMs: candidateMs };
}

export function formatLocalDateTimeInput(iso: string): string {
  const instant = new Date(iso);
  if (Number.isNaN(instant.getTime())) return "";
  const year = String(instant.getFullYear()).padStart(4, "0");
  return `${year}-${pad2(instant.getMonth() + 1)}-${pad2(instant.getDate())}T${pad2(instant.getHours())}:${pad2(instant.getMinutes())}`;
}

export function formatLocalDuePreview(iso: string): string {
  const instant = new Date(iso);
  if (Number.isNaN(instant.getTime())) return "";
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(instant);
}

export function dueInstantsEqual(
  left: string | null,
  right: string | null,
): boolean {
  if (left == null && right == null) return true;
  if (left == null || right == null) return false;
  const leftMs = Date.parse(left);
  const rightMs = Date.parse(right);
  if (Number.isNaN(leftMs) || Number.isNaN(rightMs)) return false;
  return leftMs === rightMs;
}

export function localDateTimeMessage(reason: LocalDateTimeReason): string {
  if (reason === "nonexistent") return NONEXISTENT_LOCAL_TIME;
  if (reason === "ambiguous") return AMBIGUOUS_LOCAL_TIME;
  return "Enter a valid local date and time.";
}
