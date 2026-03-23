/**
 * Auto-update intelligence feeds for skill-audit
 * 
 * This module provides automatic background updating of vulnerability
 * intelligence feeds (KEV, EPSS, NVD) when the skill is loaded.
 */

import { isCacheStale, fetchKEV, fetchEPSS, fetchNVD, saveToCache } from "./intel.js";

/**
 * Auto-update intelligence feeds if stale (silent, non-blocking)
 * Called automatically when skill is loaded in audit mode
 */
export async function ensureIntelFeedsFresh(): Promise<void> {
  const sources = ["kev", "epss", "nvd"] as const;
  
  for (const source of sources) {
    const staleInfo = isCacheStale(source);
    const stale = staleInfo?.stale ?? false;
    
    if (stale) {
      try {
        let records;
        if (source === "kev") {
          records = await fetchKEV();
        } else if (source === "epss") {
          records = await fetchEPSS();
        } else if (source === "nvd") {
          records = await fetchNVD();
        }
        if (records && records.length > 0) {
          saveToCache(source, records);
        }
      } catch {
        // Silent fail - don't interrupt audit for feed update failures
      }
    }
  }
}