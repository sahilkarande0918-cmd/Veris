import { useState } from "react"
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native"
import { router } from "expo-router"

import { EvidencePanel } from "../components/evidence-panel"
import { getLastResult } from "../lib/store"
import { colors, verdictStyle } from "../lib/theme"

export default function Result() {
  const result = getLastResult()
  const [showRegional, setShowRegional] = useState(false)

  if (!result) {
    return (
      <View style={styles.page}>
        <Text style={styles.muted}>Nothing checked yet.</Text>
      </View>
    )
  }

  const style = verdictStyle[result.verdict]
  const explanation = result.explanation

  return (
    <ScrollView contentContainerStyle={styles.page}>
      <View style={[styles.badge, { borderColor: style.color }]}>
        <Text style={[styles.badgeLabel, { color: style.color }]}>{style.label}</Text>
        <Text style={styles.badgeScore}>score {result.score} / 100</Text>
        <Text style={styles.badgeAdvice}>{style.advice}</Text>
      </View>

      <Text style={styles.subject} numberOfLines={3}>
        {result.subject.value}
      </Text>

      {explanation && (
        <View style={styles.card}>
          <View style={styles.cardHead}>
            <Text style={styles.cardTitle}>What this means</Text>
            <Pressable
              style={styles.toggle}
              onPress={() => setShowRegional((on) => !on)}
              accessibilityRole="button"
            >
              <Text style={styles.toggleText}>
                {showRegional ? "English" : explanation.language === "hi" ? "हिंदी" : "मराठी"}
              </Text>
            </Pressable>
          </View>
          <Text style={styles.body}>
            {showRegional ? explanation.regional : explanation.english}
          </Text>
          <Text style={styles.byline}>written by {explanation.generated_by}</Text>
        </View>
      )}

      <Text style={styles.sectionTitle}>Evidence</Text>
      <Text style={styles.sectionNote}>
        Every signal below came from a named source. The verdict is these
        signals added up, not an opinion.
      </Text>
      <EvidencePanel signals={result.signals} />

      <Text style={styles.sectionTitle}>Rules that fired</Text>
      <View style={styles.card}>
        {result.rules_fired.map((rule, index) => (
          <Text key={index} style={styles.rule}>
            • {rule}
          </Text>
        ))}
      </View>

      <Pressable style={styles.primary} onPress={() => router.push("/report")}>
        <Text style={styles.primaryText}>Create evidence packet</Text>
      </Pressable>

      <Text style={styles.disclaimer}>
        This is an automated assessment for your consideration, not a
        determination of guilt against any person or company. Verify
        independently before acting.
      </Text>
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  page: { padding: 18, gap: 12, backgroundColor: colors.bg, flexGrow: 1 },
  muted: { color: colors.muted },
  badge: { borderWidth: 2, borderRadius: 14, padding: 16, gap: 4, backgroundColor: colors.card },
  badgeLabel: { fontSize: 24, fontWeight: "800", letterSpacing: 1 },
  badgeScore: { color: colors.muted, fontSize: 13, fontVariant: ["tabular-nums"] },
  badgeAdvice: { color: colors.text, fontSize: 15, lineHeight: 21, marginTop: 4 },
  subject: { color: colors.muted, fontSize: 13, fontFamily: "monospace" },
  card: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    padding: 14,
    gap: 8,
  },
  cardHead: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  cardTitle: { color: colors.text, fontWeight: "700", fontSize: 16 },
  toggle: {
    borderColor: colors.accent,
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 5,
  },
  toggleText: { color: colors.accent, fontWeight: "600", fontSize: 13 },
  body: { color: colors.text, fontSize: 15, lineHeight: 23 },
  byline: { color: colors.muted, fontSize: 11, fontStyle: "italic" },
  sectionTitle: { color: colors.text, fontWeight: "700", fontSize: 17, marginTop: 8 },
  sectionNote: { color: colors.muted, fontSize: 13, lineHeight: 19, marginBottom: 2 },
  rule: { color: colors.muted, fontSize: 12, lineHeight: 19 },
  primary: {
    backgroundColor: colors.accent,
    borderRadius: 12,
    paddingVertical: 15,
    alignItems: "center",
    marginTop: 6,
  },
  primaryText: { color: "#fff", fontWeight: "700", fontSize: 16 },
  disclaimer: { color: colors.muted, fontSize: 11, lineHeight: 17, marginTop: 4 },
})
