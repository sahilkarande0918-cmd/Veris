/**
 * Read the text out of a shared screenshot, on the phone.
 *
 * "Forward the scam screenshot into Veris" is how a lot of people actually
 * ask for help -- a photo of a fake-payment SMS, a WhatsApp forward. ML Kit
 * (via expo-text-extractor) recognises the text on-device, offline, and we
 * pull the URL / UPI id / phone number out of it and run that through the
 * SAME verdict engine as any pasted link.
 *
 * On-device on purpose: the screenshot never leaves the phone to be read.
 */

import { extractTextFromImage } from "expo-text-extractor"

export { firstCandidate } from "./ocr-extract"

/** All recognised text from a screenshot, joined into one string. */
export async function textFromImage(uri: string): Promise<string> {
  const lines = await extractTextFromImage(uri)
  return lines.join(" ")
}
