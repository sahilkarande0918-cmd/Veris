/**
 * The result currently being viewed.
 *
 * ponytail: a module-level variable, not a state library. One value, one
 * writer, handed from Home to Result. Reach for context or a store the moment
 * a second screen needs to write to it.
 */

import type { VerdictResult } from "./api"

let lastResult: VerdictResult | null = null

export function setLastResult(result: VerdictResult): void {
  lastResult = result
}

export function getLastResult(): VerdictResult | null {
  return lastResult
}
