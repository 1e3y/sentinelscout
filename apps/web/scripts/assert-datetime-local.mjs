/** Keep in sync with apps/web/lib/datetime-local.ts. */
const INPUT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/;
const WINDOW_MS = 48 * 60 * 60 * 1000;
const SAMPLE_MS = 15 * 60 * 1000;

const systemClock = {
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

function daysInMonth(year, month) {
  const probe = new Date(0);
  probe.setFullYear(year, month, 0);
  return probe.getDate();
}

function parseLocalDateTimeInput(raw, clock = systemClock) {
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

  const offsets = new Set();
  const candidateMs = candidate.getTime();
  for (let t = candidateMs - WINDOW_MS; t <= candidateMs + WINDOW_MS; t += SAMPLE_MS) {
    offsets.add(clock.timezoneOffsetMinutes(new Date(t)));
  }
  const candidateOffset = clock.timezoneOffsetMinutes(candidate);
  offsets.add(candidateOffset);

  const matches = new Set([candidateMs]);
  for (const offset of offsets) {
    if (offset === candidateOffset) continue;
    const alternative = new Date(candidateMs + (offset - candidateOffset) * 60_000);
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

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  assert(actual === expected, `${message}: expected ${expected}, got ${actual}`);
}

const ordinary = parseLocalDateTimeInput("2026-06-15T14:30");
assert(ordinary.ok, "ordinary local value should be valid");
assert(ordinary.iso.endsWith("Z"), "valid result must be an aware UTC ISO instant");
assertEqual(new Date(ordinary.iso).toISOString(), ordinary.iso, "ISO round-trip");

const yearQuirk = parseLocalDateTimeInput("0024-06-15T10:30");
assert(yearQuirk.ok, "year 24 must not use the JS 1900 Date constructor quirk");
assertEqual(new Date(yearQuirk.iso).getFullYear(), 24, "constructed year");
assert(!yearQuirk.iso.includes("1924"), "must not land in 1924");

const invalidDay = parseLocalDateTimeInput("2026-02-30T10:00");
assertEqual(invalidDay.ok, false, "invalid calendar day rejected");
assertEqual(invalidDay.reason, "invalid", "invalid calendar reason");

const blank = parseLocalDateTimeInput("");
assertEqual(blank.ok, false, "blank is invalid and cannot clear");
assertEqual(blank.reason, "invalid", "blank reason");

const springForward = parseLocalDateTimeInput("2024-03-10T02:30");
assertEqual(springForward.ok, false, "nonexistent DST gap rejected");
assertEqual(springForward.reason, "nonexistent", "nonexistent reason");

const fallBack = parseLocalDateTimeInput("2024-11-03T01:30");
assertEqual(fallBack.ok, false, "60-minute DST overlap rejected");
assertEqual(fallBack.reason, "ambiguous", "ambiguous 60-minute reason");

const past = parseLocalDateTimeInput("2020-01-15T08:30");
assert(past.ok, "past local times remain permitted");
const future = parseLocalDateTimeInput("2030-01-15T08:30");
assert(future.ok, "future local times remain permitted");

const WALL = { year: 2021, monthIndex: 3, day: 4, hour: 1, minute: 30 };
const INSTANT_A = Date.UTC(2021, 3, 4, 1, 30);
const INSTANT_B = INSTANT_A - 90 * 60 * 1000;
const oddShiftClock = {
  fromWall() {
    return new Date(INSTANT_A);
  },
  partsOf(instant) {
    if (instant.getTime() === INSTANT_A || instant.getTime() === INSTANT_B) {
      return { ...WALL };
    }
    return {
      year: instant.getUTCFullYear(),
      monthIndex: instant.getUTCMonth(),
      day: instant.getUTCDate(),
      hour: instant.getUTCHours(),
      minute: instant.getUTCMinutes(),
    };
  },
  timezoneOffsetMinutes(instant) {
    const t = instant.getTime();
    if (t === INSTANT_A) return 0;
    if (t === INSTANT_B) return -90;
    return t < (INSTANT_A + INSTANT_B) / 2 ? -90 : 0;
  },
};
const oddShift = parseLocalDateTimeInput("2021-04-04T01:30", oddShiftClock);
assertEqual(oddShift.ok, false, "non-60-minute offset overlap rejected");
assertEqual(oddShift.reason, "ambiguous", "non-60-minute ambiguous reason");

const quirkDate = new Date(24, 5, 15);
assertEqual(quirkDate.getFullYear(), 1924, "control: Date(year, ...) still has the quirk");

console.log("datetime-local helper contract passed");
