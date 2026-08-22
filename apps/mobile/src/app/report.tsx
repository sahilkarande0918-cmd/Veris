import { useState } from "react"
import {
  ActivityIndicator,
  Linking,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native"

import { submitReport } from "../lib/api"
import { getLastResult } from "../lib/store"
import { colors } from "../lib/theme"
import { useSecureScreen } from "../lib/secureScreen"

/** NCRP asks for these. All optional: a victim in the golden hour will not have them all. */
const FIELDS = [
  { key: "amount_lost", label: "Amount lost (INR)", keyboard: "numeric" as const },
  { key: "payment_mode", label: "Payment mode (UPI / IMPS / card)" },
  { key: "suspect_upi_id", label: "Suspect UPI id" },
  { key: "suspect_account_number", label: "Suspect account number" },
  { key: "suspect_bank_or_wallet", label: "Suspect bank or wallet" },
  { key: "transaction_reference", label: "Transaction reference (UTR)" },
  { key: "suspect_phone", label: "Suspect phone" },
  { key: "description", label: "What happened", multiline: true },
]

export default function Report() {
  useSecureScreen() // FLAG_SECURE on the complaint/report screen (off unless extra.secureScreens)
  const result = getLastResult()
  const [values, setValues] = useState<Record<string, string>>({
    suspect_upi_id: result?.subject.type === "upi" ? result.subject.value : "",
  })
  const [packet, setPacket] = useState<Record<string, unknown> | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function generate() {
    setBusy(true)
    setError(null)
    try {
      const complaint: Record<string, unknown> = {
        incident_datetime: new Date().toISOString(),
        suspect_urls:
          result && (result.subject.type === "url" || result.subject.type === "domain")
            ? [result.subject.value]
            : [],
      }
      for (const [key, value] of Object.entries(values)) {
        if (!value.trim()) continue
        complaint[key] = key === "amount_lost" ? Number(value) : value.trim()
      }
      setPacket(await submitReport(complaint))
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught))
    } finally {
      setBusy(false)
    }
  }

  const ledger = packet?.evidence_ledger as Record<string, unknown> | undefined

  return (
    <ScrollView contentContainerStyle={styles.page} keyboardShouldPersistTaps="handled">
      <Text style={styles.note}>
        Veris does not file anything for you. This builds a packet you can read
        out to 1930 or transcribe into the NCRP portal yourself.
      </Text>

      {FIELDS.map((field) => (
        <View key={field.key} style={styles.field}>
          <Text style={styles.label}>{field.label}</Text>
          <TextInput
            style={[styles.input, field.multiline && styles.multiline]}
            value={values[field.key] ?? ""}
            onChangeText={(text) => setValues((prev) => ({ ...prev, [field.key]: text }))}
            keyboardType={field.keyboard ?? "default"}
            multiline={field.multiline}
            autoCapitalize="none"
            placeholderTextColor={colors.muted}
          />
        </View>
      ))}

      <Pressable
        style={({ pressed }) => [styles.primary, pressed && { opacity: 0.8 }]}
        onPress={generate}
        disabled={busy}
      >
        {busy ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.primaryText}>Generate evidence packet</Text>
        )}
      </Pressable>

      {error && <Text style={styles.error}>{error}</Text>}

      {/* `packet &&` is load-bearing: it narrows packet for the findings count below. */}
      {packet && ledger && (
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Packet ready</Text>
          <Text style={styles.kv}>
            chain verified: {String(ledger.chain_verified)}
          </Text>
          <Text style={styles.kv} numberOfLines={1}>
            head: {String(ledger.head_hash ?? "-").slice(0, 40)}...
          </Text>
          <Text style={styles.kv}>
            findings attached: {(packet.automated_findings as unknown[])?.length ?? 0}
          </Text>
          <Text style={styles.hint}>
            The packet includes every signal with its source, and the hash chain
            status so the recipient can check it was not edited.
          </Text>

          <Pressable
            style={styles.secondary}
            onPress={() => Linking.openURL("https://cybercrime.gov.in/")}
          >
            <Text style={styles.secondaryText}>Open cybercrime.gov.in</Text>
          </Pressable>
          <Pressable style={styles.secondary} onPress={() => Linking.openURL("tel:1930")}>
            <Text style={styles.secondaryText}>Call 1930 helpline</Text>
          </Pressable>
          <Pressable
            style={styles.secondary}
            onPress={() => Linking.openURL("https://sancharsaathi.gov.in/")}
          >
            <Text style={styles.secondaryText}>Report the number on Sanchar Saathi</Text>
          </Pressable>
          <Text style={styles.rails}>
            These open the official portals. Veris never files a report for you
            and never contacts an officer on your behalf — none of these have a
            public API, and the decision to report is yours.
          </Text>
        </View>
      )}
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  page: { padding: 18, gap: 12, backgroundColor: colors.bg, flexGrow: 1 },
  note: { color: colors.muted, fontSize: 14, lineHeight: 20 },
  field: { gap: 5 },
  label: { color: colors.muted, fontSize: 13 },
  input: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 10,
    color: colors.text,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 15,
  },
  multiline: { minHeight: 80, textAlignVertical: "top" },
  primary: {
    backgroundColor: colors.accent,
    borderRadius: 12,
    paddingVertical: 15,
    alignItems: "center",
    marginTop: 6,
  },
  primaryText: { color: "#fff", fontWeight: "700", fontSize: 16 },
  error: { color: colors.danger, fontSize: 13 },
  card: {
    backgroundColor: colors.card,
    borderColor: colors.cardEdge,
    borderWidth: 1,
    borderRadius: 12,
    padding: 14,
    gap: 7,
  },
  cardTitle: { color: colors.text, fontWeight: "700", fontSize: 16 },
  kv: { color: colors.muted, fontSize: 13, fontFamily: "monospace" },
  hint: { color: colors.muted, fontSize: 13, lineHeight: 19 },
  secondary: {
    borderColor: colors.accent,
    borderWidth: 1,
    borderRadius: 10,
    paddingVertical: 12,
    alignItems: "center",
  },
  secondaryText: { color: colors.accent, fontWeight: "600", fontSize: 14 },
  rails: { color: colors.muted, fontSize: 12, lineHeight: 18, marginTop: 2 },
})
