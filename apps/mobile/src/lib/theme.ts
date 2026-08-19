/** Colours and shared styles. Dark, high-contrast, readable in sunlight. */

import type { Verdict } from "./api"

export const colors = {
  bg: "#0B1220",
  card: "#141C2E",
  cardEdge: "#22304C",
  text: "#E8EDF7",
  muted: "#93A2BF",
  accent: "#4C8DFF",
  danger: "#FF5C5C",
  warn: "#FFB020",
  safe: "#2ECC8F",
}

export const verdictStyle: Record<Verdict, { label: string; color: string; advice: string }> = {
  likely_scam: {
    label: "LIKELY SCAM",
    color: colors.danger,
    advice: "Do not share an OTP, personal details, or money.",
  },
  suspicious: {
    label: "SUSPICIOUS",
    color: colors.warn,
    advice: "Verify through the official app or website before acting.",
  },
  safe: {
    label: "NO FLAGS FOUND",
    color: colors.safe,
    advice: "Nothing flagged this. Stay alert anyway.",
  },
}
