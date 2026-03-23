/**
 * Auto-update intelligence feeds for skill-audit
 *
 * This module provides automatic background updating of vulnerability
 * intelligence feeds (KEV, EPSS, NVD) when the skill is loaded.
 * 
 * Features:
 * - Lazy background update (non-blocking via setTimeout)
 * - Graceful degradation (use stale cache if fetch fails)
 * - Verbose mode for transparency
 */

import { isCacheStale, fetchKEV, fetchEPSS, fetchNVD, saveToCache } from "./intel.js";

export interface AutoUpdateOptions {
  /** Enable verbose logging (default: false) */
  verbose?: boolean;
  /** Timeout in ms before giving up on fetch (default: 5000) */
  timeout?: number;
  /** Delay before starting update in ms (default: 100) */
  delay?: number;
}

const DEFAULT_OPTIONS: Required<AutoUpdateOptions> = {
  verbose: false,
  timeout: 5000,
  delay: 100
};

/**
 * Log message if verbose mode is enabled
 */
function log(verbose: boolean, ...args: unknown[]): void {
  if (verbose) {
    console.log("[auto-update]", ...args);
  }
}

/**
 * Auto-update intelligence feeds if stale (lazy, non-blocking)
 * 
 * Uses setTimeout to defer execution, ensuring it doesn't block
 * the main thread or hook execution.
 * 
 * @param options - Configuration options
 * @returns Promise that resolves immediately (actual update happens in background)
 */
export function ensureIntelFeedsFresh(options: AutoUpdateOptions = {}): Promise<void> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  
  // Return immediately - actual work happens in background
  return new Promise((resolve) => {
    setTimeout(async () => {
      await updateFeeds(opts);
    }, opts.delay);
    
    // Resolve immediately to not block caller
    resolve();
  });
}

/**
 * Internal function that performs the actual update
 */
async function updateFeeds(opts: Required<AutoUpdateOptions>): Promise<void> {
  const sources = ["kev", "epss", "nvd"] as const;

  for (const source of sources) {
    const staleInfo = isCacheStale(source);
    const stale = staleInfo?.stale ?? false;

    if (stale) {
      log(opts.verbose, `Cache stale for ${source}, fetching...`);
      
      try {
        // Create timeout promise
        const timeoutPromise = new Promise<never>((_, reject) => {
          setTimeout(() => reject(new Error(`Timeout after ${opts.timeout}ms`)), opts.timeout);
        });

        let records;
        const fetchPromise = source === "kev" 
          ? fetchKEV() 
          : source === "epss" 
            ? fetchEPSS() 
            : fetchNVD();

        // Race between fetch and timeout
        records = await Promise.race([fetchPromise, timeoutPromise]);

        if (records && records.length > 0) {
          saveToCache(source, records);
          log(opts.verbose, `Updated ${source}: ${records.length} records`);
        }
      } catch (error) {
        // Graceful degradation: use stale cache with warning
        const age = staleInfo?.age?.toFixed(1) ?? "unknown";
        log(opts.verbose, `Failed to update ${source}, using stale cache (${age} days old):`, 
          error instanceof Error ? error.message : "Unknown error");
        // Don't throw - continue with stale cache
      }
    } else {
      log(opts.verbose, `Cache fresh for ${source}`);
    }
  }
}

/**
 * Check if feeds need update without actually updating
 * Useful for showing status to users
 */
export function getFeedStatus(): Array<{
  source: string;
  stale: boolean;
  age?: number;
  warn: boolean;
}> {
  const sources = ["kev", "epss", "nvd"] as const;
  return sources.map(source => {
    const info = isCacheStale(source);
    return {
      source,
      stale: info?.stale ?? true,
      age: info?.age,
      warn: info?.warn ?? false
    };
  });
}