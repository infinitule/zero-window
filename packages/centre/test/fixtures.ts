import type { Blueprint, ItemBank } from "@zw/authority";

/** Mirrors the authority test fixture: blueprint-satisfiable with margin. */
export function sampleBank(examId = "EXAM-2026-PHYS"): ItemBank {
  const items = [];
  for (const subject of ["mechanics", "optics"]) {
    for (const difficulty of ["easy", "medium", "hard"] as const) {
      for (let i = 0; i < 8; i++) {
        items.push({
          id: `${subject}-${difficulty}-${i}`,
          subject,
          difficulty,
          body:
            `A ${difficulty} ${subject} question number ${i}: a body long enough to ` +
            `exercise word wrapping across the printable width of an A4 page with ` +
            `margins, including some numbers like ${i * 37} and units such as m/s².`,
          options: [
            `first candidate answer for item ${i}`,
            `second candidate answer, deliberately longer to wrap when indented under its label`,
            `third answer ${i}`,
            `fourth answer ${i}`,
          ],
          correctIndex: i % 4,
        });
      }
    }
  }
  return { examId, items };
}

export function sampleBlueprint(examId = "EXAM-2026-PHYS"): Blueprint {
  return {
    examId,
    title: "Physics Paper I — Mechanics and Optics",
    durationMinutes: 180,
    slots: [
      { subject: "mechanics", difficulty: "easy", count: 4 },
      { subject: "mechanics", difficulty: "medium", count: 4 },
      { subject: "mechanics", difficulty: "hard", count: 2 },
      { subject: "optics", difficulty: "easy", count: 4 },
      { subject: "optics", difficulty: "medium", count: 4 },
      { subject: "optics", difficulty: "hard", count: 2 },
    ],
  };
}
