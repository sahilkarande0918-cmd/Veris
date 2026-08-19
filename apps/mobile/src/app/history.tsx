import { useCallback, useState } from "react"
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View } from "react-native"
import { useFocusEffect } from "expo-router"

import { ledgerEvents, verifyChain, type ChainStatus, type LedgerEvent } from "../lib/api"
import { colors } from "../lib/theme"

export default function History() {
  const [events, setEvents] = useState<LedgerEvent[]>([])
  const [chain, setChain] = useState<ChainStatus | null>(null)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const [listed, status] = await Promise.all([ledgerEvents(), verifyChain()])
      setEvents(listed.events)
      setChain(status)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught))
    } finally {
      setBusy(false)
    }
  }, [])

  useFocusEffect(
    useCallback(() => {
      void load()
    }, [load]),
  )

  return (
    <ScrollView contentContainerStyle={styles.page}>
      {chain && (
        <View style={[styles.chain, { borderColor: chain.ok ? colors.safe : colors.danger }]}>
          <Text style={[styles.chainTitle, { color: chain.ok ? colors.safe : colors.danger }]}>
            {chain.ok ? "CHAIN INTACT" : `TAMPERING DETECTED AT RECORD ${chain.broken_at}`}
          </Text>
          <Text style={styles.chainReason}>{chain.reason}</Text>
          <Text style={styles.mono}>{chain.count} record(s)</Text>
          {chain.head_hash && (
            <Text style={styles.mono} numberOfLines={1}>
              head {chain.head_hash.slice(0, 32)}...
            </Text>
          )}
        </View>
      )}

      <Pressable style={styles.refresh} onPress={load}>
        <Text style={styles.refreshText}>Re-verify chain</Text>
      </Pressable>

      {busy && <ActivityIndicator color={colors.accent} />}
      {error && <Text style={styles.error}>{error}</Text>}

      {events
        .slice()
        .reverse()
        .map((event) => {
          const payload = event.payload as Record<string, unknown>
          const subject = payload.subject as { value?: string } | undefined
          return (
            <View key={event.hash} style={styles.row}>
              <View style={styles.rowHead}>
                <Text style={styles.seq}>#{event.seq}</Text>
                <Text style={styles.type}>{event.event_type}</Text>
              </View>
              {subject?.value && (
                <Text style={styles.subject} numberOfLines={2}>
                  {subject.value}
                </Text>
              )}
              {payload.verdict != null && (
                <Text style={styles.verdict}>
                  {String(payload.verdict)} · score {String(payload.score ?? "-")}
                </Text>
              )}
              <Text style={styles.mono} numberOfLines={1}>
                hash {event.hash.slice(0, 24)}...
              </Text>
              <Text style={styles.mono} numberOfLines={1}>
                prev {event.prev_hash.slice(0, 24)}...
              </Text>
            </View>
          )
        })}

      {!busy && events.length === 0 && !error && (
        <Text style={styles.empty}>No events recorded yet.</Text>
      )}
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  page: { padding: 18, gap: 11, backgroundColor: colors.bg, flexGrow: 1 },
  chain: { borderWidth: 2, borderRadius: 12, padding: 14, gap: 4, backgroundColor: colors.card },
  chainTitle: { fontWeight: "800", fontSize: 16, letterSpacing: 0.5 },
  chainReason: { color: colors.text, fontSize: 13, lineHeight: 19 },
  refresh: {
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 10,
    paddingVertical: 11,
    alignItems: "center",
  },
  refreshText: { color: colors.text, fontWeight: "600", fontSize: 14 },
  row: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    padding: 12,
    gap: 3,
  },
  rowHead: { flexDirection: "row", justifyContent: "space-between" },
  seq: { color: colors.accent, fontWeight: "700", fontSize: 14 },
  type: { color: colors.muted, fontSize: 12, textTransform: "uppercase" },
  subject: { color: colors.text, fontSize: 14 },
  verdict: { color: colors.muted, fontSize: 13 },
  mono: { color: colors.muted, fontSize: 11, fontFamily: "monospace" },
  error: { color: colors.danger, fontSize: 13 },
  empty: { color: colors.muted, fontSize: 14, textAlign: "center", marginTop: 20 },
})
