/**
 * Investigator console — Email Threat Forensics [SIH26106 #9].
 *
 * Paste/analyze a raw .eml -> forensic dashboard: colour-coded verdict + fraud
 * score, SPF/DKIM/DMARC indicators, sender trace path + geolocation, domain
 * intelligence, attribution, and the cited evidence. Reads as an analyst tool.
 * Pure presentation over the /check/email endpoint; no verdict logic here.
 */
import { useState } from "react"
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  View,
} from "react-native"
import { LinearGradient } from "expo-linear-gradient"

import { checkEmail, type EmailResult } from "../lib/api"
import { light } from "../lib/theme"

const SAMPLE = `Return-Path: <bounce@mailer-xyz.ru>
Received: from mx.recipient.gov.in (mx.recipient.gov.in [10.0.0.5]) by inbound.recipient.gov.in with ESMTP id A1B2C3; Sat, 22 Aug 2026 09:00:05 +0530
Received: from smtp.mailer-xyz.ru (unknown [185.220.101.5]) by mx.recipient.gov.in with ESMTP id D4E5F6; Sat, 22 Aug 2026 09:00:03 +0530
Authentication-Results: mx.recipient.gov.in; spf=fail smtp.mailfrom=mailer-xyz.ru; dkim=fail; dmarc=fail header.from=hdfcbank-secure.top
From: "HDFC Bank Secure" <alerts@hdfcbank-secure.top>
Reply-To: <recover@gmail-support.info>
To: victim@recipient.gov.in
Subject: Urgent: Your account will be blocked - verify KYC now
Message-ID: <20260822.abc123@mailer-xyz.ru>
Date: Sat, 22 Aug 2026 09:00:00 +0530
Content-Type: text/plain; charset="utf-8"

Dear Customer, your account will be suspended within 24 hours. Verify your KYC:
https://xn--icicibnk-66g.com/login`

const VERDICT_UI: Record<string, { label: string; fg: string; bg: string }> = {
  likely_scam: { label: "FRAUD", fg: light.danger, bg: light.dangerBg },
  suspicious: { label: "SUSPICIOUS", fg: light.warn, bg: light.warnBg },
  safe: { label: "LEGITIMATE", fg: light.safe, bg: light.safeBg },
}

function authColor(v: string): string {
  return /pass/.test(v) ? light.safe : light.danger
}

export default function EmailForensics() {
  const [raw, setRaw] = useState("")
  const [mask, setMask] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<EmailResult | null>(null)

  async function analyze() {
    if (!raw.trim() || busy) return
    setBusy(true)
    setError(null)
    try {
      setResult(await checkEmail(raw, { language: "en", mask }))
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed. Check the Engine URL in Protection settings.")
      setResult(null)
    } finally {
      setBusy(false)
    }
  }

  const f = result?.email_forensics
  const vu = result ? VERDICT_UI[result.verdict] ?? VERDICT_UI.suspicious : null

  return (
    <View style={styles.root}>
      <LinearGradient colors={[light.bgMid, light.bg, light.white]} locations={[0, 0.18, 0.4]} style={StyleSheet.absoluteFill} />
      <ScrollView contentContainerStyle={styles.page} keyboardShouldPersistTaps="handled">
        <Text style={styles.h1}>Email Threat Forensics</Text>
        <Text style={styles.sub}>Investigator console — paste a raw email (.eml) to trace, verify and attribute it.</Text>

        <TextInput
          style={styles.input}
          placeholder="Paste raw email headers + body here…"
          placeholderTextColor={light.faint}
          value={raw}
          onChangeText={setRaw}
          multiline
          autoCapitalize="none"
          autoCorrect={false}
        />
        <View style={styles.row}>
          <Pressable style={styles.ghost} onPress={() => setRaw(SAMPLE)}>
            <Text style={styles.ghostText}>Load sample</Text>
          </Pressable>
          <View style={styles.maskRow}>
            <Text style={styles.maskLabel}>Mask PII</Text>
            <Switch value={mask} onValueChange={setMask} trackColor={{ true: light.primary }} />
          </View>
        </View>
        <Pressable style={[styles.primary, busy && { opacity: 0.6 }]} onPress={analyze} disabled={busy}>
          {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.primaryText}>Analyze email</Text>}
        </Pressable>

        {error && (
          <View style={styles.errorBox}>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        )}

        {result && f && vu && (
          <View style={{ gap: 12 }}>
            {/* proactive high-risk alert */}
            {result.verdict === "likely_scam" && (
              <View style={styles.alert}>
                <Text style={styles.alertText}>⚠ HIGH-RISK EMAIL — do not act on it. Flagged before any user interaction.</Text>
              </View>
            )}

            {/* verdict hero */}
            <View style={[styles.hero, { backgroundColor: vu.bg, borderColor: vu.fg }]}>
              <View style={styles.heroTop}>
                <Text style={[styles.verdictLabel, { color: vu.fg }]}>{vu.label}</Text>
                <View style={[styles.chip, { backgroundColor: "#fff" }]}>
                  <Text style={[styles.chipText, { color: vu.fg }]}>{f.classification}</Text>
                </View>
              </View>
              <Text style={styles.subject} numberOfLines={2}>{f.subject || "(no subject)"}</Text>
              <Text style={styles.fromLine}>from {f.from_addr}{f.pii_masked ? "  · PII masked" : ""}</Text>
              <View style={styles.scoreTrack}>
                <View style={[styles.scoreFill, { width: `${Math.min(100, result.score)}%`, backgroundColor: vu.fg }]} />
              </View>
              <Text style={[styles.score, { color: vu.fg }]}>risk score {result.score}/100</Text>
            </View>

            {/* authentication */}
            <View style={styles.card}>
              <Text style={styles.cardTitle}>Authentication</Text>
              <View style={styles.authRow}>
                {["spf", "dkim", "dmarc"].map((k) => (
                  <View key={k} style={styles.authChip}>
                    <Text style={styles.authName}>{k.toUpperCase()}</Text>
                    <Text style={[styles.authVal, { color: authColor(f.auth_results?.[k] ?? "none") }]}>{f.auth_results?.[k] ?? "—"}</Text>
                  </View>
                ))}
              </View>
            </View>

            {/* sender trace + geolocation */}
            <View style={styles.card}>
              <Text style={styles.cardTitle}>Sender trace &amp; origin</Text>
              <View style={styles.trace}>
                <View style={styles.traceNode}><Text style={styles.traceIp}>{f.originating_ip || "?"}</Text><Text style={styles.traceCap}>origin</Text></View>
                <View style={styles.traceLine} />
                <View style={styles.traceNode}><Text style={styles.traceIp}>{f.received_hops ?? 0} hops</Text><Text style={styles.traceCap}>relays</Text></View>
                <View style={styles.traceLine} />
                <View style={styles.traceNode}><Text style={styles.traceIp}>inbox</Text><Text style={styles.traceCap}>recipient</Text></View>
              </View>
              {f.geo?.country ? (
                <Text style={styles.geo}>📍 {[f.geo.city, f.geo.country].filter(Boolean).join(", ")} · {f.geo.org || f.geo.isp} {f.geo.asn || ""}</Text>
              ) : null}
            </View>

            {/* domain intelligence */}
            {f.domain_intel?.registrar ? (
              <View style={styles.card}>
                <Text style={styles.cardTitle}>Domain intelligence</Text>
                <Text style={styles.kv}>registrar: {f.domain_intel.registrar}</Text>
                <Text style={styles.kv}>age: {f.domain_intel.age_days} days{typeof f.domain_intel.age_days === "number" && f.domain_intel.age_days <= 30 ? "  ⚠ freshly registered" : ""}</Text>
                <Text style={styles.kv}>MX: {f.domain_intel.mx && f.domain_intel.mx.length ? f.domain_intel.mx.join(", ") : "none ⚠"}</Text>
              </View>
            ) : null}

            {/* cited evidence */}
            <View style={styles.card}>
              <Text style={styles.cardTitle}>Cited evidence · {result.signals.filter((s) => s.weight > 0).length} signals</Text>
              {result.signals.filter((s) => s.weight > 0).sort((a, b) => b.weight - a.weight).map((s, i) => (
                <View key={i} style={styles.sig}>
                  <View style={styles.sigWeight}><Text style={styles.sigWeightText}>+{s.weight}</Text></View>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.sigVal} numberOfLines={2}>{s.value}</Text>
                    <Text style={styles.sigSrc}>{s.source}</Text>
                  </View>
                </View>
              ))}
            </View>

            {result.explanation?.english ? (
              <View style={styles.card}>
                <Text style={styles.cardTitle}>What this means</Text>
                <Text style={styles.explain}>{result.explanation.english}</Text>
              </View>
            ) : null}
          </View>
        )}
      </ScrollView>
    </View>
  )
}

const shadow = { shadowColor: "#1e293b", shadowOpacity: 0.08, shadowRadius: 12, shadowOffset: { width: 0, height: 5 }, elevation: 2 }

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: light.white },
  page: { padding: 18, paddingTop: 16, gap: 12 },
  h1: { fontSize: 24, fontWeight: "800", color: light.ink, letterSpacing: -0.5 },
  sub: { fontSize: 13, color: light.muted, lineHeight: 19 },
  input: { backgroundColor: light.card, borderColor: light.line, borderWidth: 1, borderRadius: 14, color: light.ink, padding: 13, minHeight: 130, fontSize: 12, fontFamily: "monospace", textAlignVertical: "top", ...shadow },
  row: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  ghost: { paddingVertical: 9, paddingHorizontal: 14, borderRadius: 12, borderWidth: 1, borderColor: light.line, backgroundColor: light.card },
  ghostText: { color: light.primaryDark, fontWeight: "700", fontSize: 13 },
  maskRow: { flexDirection: "row", alignItems: "center", gap: 8 },
  maskLabel: { color: light.muted, fontSize: 13, fontWeight: "600" },
  primary: { backgroundColor: light.primaryDark, borderRadius: 14, paddingVertical: 15, alignItems: "center", ...shadow },
  primaryText: { color: "#fff", fontWeight: "700", fontSize: 15 },
  errorBox: { backgroundColor: light.dangerBg, borderColor: "#fecaca", borderWidth: 1, borderRadius: 12, padding: 12 },
  errorText: { color: "#b91c1c", fontSize: 13, lineHeight: 19 },
  alert: { backgroundColor: "#dc2626", borderRadius: 12, padding: 12 },
  alertText: { color: "#fff", fontWeight: "700", fontSize: 13 },
  hero: { borderRadius: 20, borderWidth: 1.5, padding: 18, ...shadow },
  heroTop: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  verdictLabel: { fontSize: 22, fontWeight: "800", letterSpacing: 0.5 },
  chip: { borderRadius: 20, paddingVertical: 4, paddingHorizontal: 11 },
  chipText: { fontSize: 12, fontWeight: "700", textTransform: "capitalize" },
  subject: { marginTop: 12, fontSize: 15, fontWeight: "700", color: light.ink },
  fromLine: { fontSize: 12, color: light.muted, marginTop: 3, fontFamily: "monospace" },
  scoreTrack: { height: 8, borderRadius: 5, backgroundColor: "#ffffff", marginTop: 12, overflow: "hidden" },
  scoreFill: { height: "100%", borderRadius: 5 },
  score: { fontSize: 12, fontWeight: "700", marginTop: 5 },
  card: { backgroundColor: light.card, borderColor: light.line, borderWidth: 1, borderRadius: 16, padding: 14, gap: 6, ...shadow },
  cardTitle: { fontSize: 13, fontWeight: "800", color: light.ink, marginBottom: 4 },
  authRow: { flexDirection: "row", gap: 10 },
  authChip: { flex: 1, backgroundColor: light.bg, borderRadius: 10, paddingVertical: 8, alignItems: "center" },
  authName: { fontSize: 11, color: light.muted, fontWeight: "700" },
  authVal: { fontSize: 13, fontWeight: "800", marginTop: 2 },
  trace: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginVertical: 4 },
  traceNode: { alignItems: "center" },
  traceIp: { fontSize: 12, fontWeight: "700", color: light.ink, fontFamily: "monospace" },
  traceCap: { fontSize: 10, color: light.faint, marginTop: 2 },
  traceLine: { flex: 1, height: 2, backgroundColor: light.line, marginHorizontal: 6 },
  geo: { marginTop: 8, fontSize: 12.5, color: light.muted, fontWeight: "600" },
  kv: { fontSize: 12.5, color: light.muted },
  sig: { flexDirection: "row", gap: 10, alignItems: "flex-start", paddingVertical: 5 },
  sigWeight: { backgroundColor: light.dangerBg, borderRadius: 8, paddingVertical: 2, paddingHorizontal: 7, minWidth: 34, alignItems: "center" },
  sigWeightText: { color: "#b91c1c", fontWeight: "800", fontSize: 12 },
  sigVal: { fontSize: 12.5, color: light.ink, fontWeight: "600", lineHeight: 17 },
  sigSrc: { fontSize: 11, color: light.faint },
  explain: { fontSize: 13.5, color: light.muted, lineHeight: 20 },
})
