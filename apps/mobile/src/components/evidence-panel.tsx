import { StyleSheet, Text, View } from "react-native"

import type { Signal } from "../lib/api"
import { colors } from "../lib/theme"

/**
 * The evidence panel: every signal with the source that produced it.
 *
 * This is the screen that answers "how do you know?", so the source and the
 * timestamp are always shown, never hidden behind a tap.
 */
export function EvidencePanel({ signals }: { signals: Signal[] }) {
  if (signals.length === 0) {
    return (
      <View style={styles.empty}>
        <Text style={styles.emptyText}>
          No blocklist, impersonation, or format check flagged this.
        </Text>
      </View>
    )
  }

  return (
    <View style={styles.list}>
      {signals.map((signal, index) => (
        <View key={`${signal.id}-${index}`} style={styles.row}>
          <View style={styles.rowHead}>
            <Text style={styles.signalId}>{signal.id.replace(/_/g, " ")}</Text>
            {signal.weight > 0 && <Text style={styles.weight}>+{signal.weight}</Text>}
          </View>
          <Text style={styles.value}>{signal.value}</Text>
          <Text style={styles.source}>{signal.source}</Text>
          <Text style={styles.time}>{formatTime(signal.observed_at)}</Text>
        </View>
      ))}
    </View>
  )
}

function formatTime(iso: string): string {
  const parsed = new Date(iso)
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleString()
}

const styles = StyleSheet.create({
  list: { gap: 10 },
  row: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    padding: 12,
    gap: 3,
  },
  rowHead: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  signalId: {
    color: colors.accent,
    fontWeight: "700",
    fontSize: 13,
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },
  weight: { color: colors.muted, fontSize: 12, fontVariant: ["tabular-nums"] },
  value: { color: colors.text, fontSize: 15, lineHeight: 21 },
  source: { color: colors.muted, fontSize: 12, fontStyle: "italic" },
  time: { color: colors.muted, fontSize: 11 },
  empty: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    padding: 14,
  },
  emptyText: { color: colors.muted, fontSize: 14 },
})
