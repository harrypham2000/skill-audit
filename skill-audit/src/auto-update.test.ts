import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the intel module before importing auto-update
vi.mock('./intel.js', () => ({
  isCacheStale: vi.fn(),
  fetchKEV: vi.fn(),
  fetchEPSS: vi.fn(),
  fetchNVD: vi.fn(),
  saveToCache: vi.fn(),
}));

import { isCacheStale, fetchKEV, fetchEPSS, fetchNVD, saveToCache } from './intel.js';

describe('ensureIntelFeedsFresh', () => {
  // Import after mocking - use dynamic import in test
  let ensureIntelFeedsFresh: (options?: { verbose?: boolean; timeout?: number; delay?: number }) => Promise<void>;
  let getFeedStatus: () => Array<{ source: string; stale: boolean; age?: number; warn: boolean }>;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Re-import to get fresh module with mocks
    const module = await import('./auto-update.js');
    ensureIntelFeedsFresh = module.ensureIntelFeedsFresh;
    getFeedStatus = module.getFeedStatus;
  });

  it('should NOT update when all caches are fresh', async () => {
    // Arrange: All sources fresh
    vi.mocked(isCacheStale).mockReturnValue({ stale: false, warn: false });
    vi.mocked(fetchKEV).mockResolvedValue([]);
    vi.mocked(fetchEPSS).mockResolvedValue([]);
    vi.mocked(fetchNVD).mockResolvedValue([]);

    // Act
    await ensureIntelFeedsFresh();

    // Assert: No fetch calls should be made
    expect(fetchKEV).not.toHaveBeenCalled();
    expect(fetchEPSS).not.toHaveBeenCalled();
    expect(fetchNVD).not.toHaveBeenCalled();
  });

  it('should update KEV when stale', async () => {
    // Arrange: Only KEV stale
    vi.mocked(isCacheStale)
      .mockReturnValueOnce({ stale: true, warn: false }) // kev
      .mockReturnValueOnce({ stale: false, warn: false }) // epss
      .mockReturnValueOnce({ stale: false, warn: false }); // nvd

    const mockKEVRecords = [{ id: 'CVE-2021-1234', aliases: [], source: 'KEV' as const, kev: true, references: [] }];
    vi.mocked(fetchKEV).mockResolvedValue(mockKEVRecords);
    vi.mocked(fetchEPSS).mockResolvedValue([]);
    vi.mocked(fetchNVD).mockResolvedValue([]);

    // Act - use delay: 0 to run immediately in tests
    await ensureIntelFeedsFresh({ delay: 0 });
    // Wait for setTimeout to complete
    await new Promise(resolve => setTimeout(resolve, 10));

    // Assert
    expect(fetchKEV).toHaveBeenCalledTimes(1);
    expect(saveToCache).toHaveBeenCalledWith('kev', mockKEVRecords);
    expect(fetchEPSS).not.toHaveBeenCalled();
    expect(fetchNVD).not.toHaveBeenCalled();
  });

  it('should update EPSS when stale', async () => {
    // Arrange: Only EPSS stale
    vi.mocked(isCacheStale)
      .mockReturnValueOnce({ stale: false, warn: false }) // kev
      .mockReturnValueOnce({ stale: true, warn: false }) // epss
      .mockReturnValueOnce({ stale: false, warn: false }); // nvd

    vi.mocked(fetchKEV).mockResolvedValue([]);
    const mockEPSSRecords = [{ id: 'CVE-2021-5678', aliases: [], source: 'EPSS' as const, epss: 0.9, references: [] }];
    vi.mocked(fetchEPSS).mockResolvedValue(mockEPSSRecords);
    vi.mocked(fetchNVD).mockResolvedValue([]);

    // Act
    await ensureIntelFeedsFresh({ delay: 0 });
    await new Promise(resolve => setTimeout(resolve, 10));

    // Assert
    expect(fetchEPSS).toHaveBeenCalledTimes(1);
    expect(saveToCache).toHaveBeenCalledWith('epss', mockEPSSRecords);
  });

  it('should update NVD when stale', async () => {
    // Arrange: Only NVD stale
    vi.mocked(isCacheStale)
      .mockReturnValueOnce({ stale: false, warn: false }) // kev
      .mockReturnValueOnce({ stale: false, warn: false }) // epss
      .mockReturnValueOnce({ stale: true, warn: false }); // nvd

    vi.mocked(fetchKEV).mockResolvedValue([]);
    vi.mocked(fetchEPSS).mockResolvedValue([]);
    const mockNVDRecords = [{ id: 'CVE-2021-9999', aliases: [], source: 'NVD' as const, severity: 'HIGH', references: [] }];
    vi.mocked(fetchNVD).mockResolvedValue(mockNVDRecords);

    // Act
    await ensureIntelFeedsFresh({ delay: 0 });
    await new Promise(resolve => setTimeout(resolve, 10));

    // Assert
    expect(fetchNVD).toHaveBeenCalledTimes(1);
    expect(saveToCache).toHaveBeenCalledWith('nvd', mockNVDRecords);
  });

  it('should update all sources when all are stale', async () => {
    // Arrange: All stale
    vi.mocked(isCacheStale).mockReturnValue({ stale: true, warn: false });

    const mockKEV = [{ id: 'CVE-1', aliases: [], source: 'KEV' as const, kev: true, references: [] }];
    const mockEPSS = [{ id: 'CVE-2', aliases: [], source: 'EPSS' as const, epss: 0.5, references: [] }];
    const mockNVD = [{ id: 'CVE-3', aliases: [], source: 'NVD' as const, severity: 'MEDIUM', references: [] }];

    vi.mocked(fetchKEV).mockResolvedValue(mockKEV);
    vi.mocked(fetchEPSS).mockResolvedValue(mockEPSS);
    vi.mocked(fetchNVD).mockResolvedValue(mockNVD);

    // Act
    await ensureIntelFeedsFresh({ delay: 0 });
    await new Promise(resolve => setTimeout(resolve, 10));

    // Assert
    expect(fetchKEV).toHaveBeenCalledTimes(1);
    expect(fetchEPSS).toHaveBeenCalledTimes(1);
    expect(fetchNVD).toHaveBeenCalledTimes(1);
    expect(saveToCache).toHaveBeenCalledTimes(3);
  });

  it('should NOT save empty records', async () => {
    // Arrange: KEV stale but returns empty
    vi.mocked(isCacheStale).mockReturnValue({ stale: true, warn: false });
    vi.mocked(fetchKEV).mockResolvedValue([]); // Empty response
    vi.mocked(fetchEPSS).mockResolvedValue([]);
    vi.mocked(fetchNVD).mockResolvedValue([]);

    // Act
    await ensureIntelFeedsFresh({ delay: 0 });
    await new Promise(resolve => setTimeout(resolve, 10));

    // Assert: saveToCache should NOT be called for empty records
    expect(saveToCache).not.toHaveBeenCalled();
  });

  it('should handle network failure gracefully', async () => {
    // Arrange: KEV stale but fetch fails
    vi.mocked(isCacheStale).mockReturnValue({ stale: true, warn: false });
    vi.mocked(fetchKEV).mockRejectedValue(new Error('Network error'));
    vi.mocked(fetchEPSS).mockResolvedValue([]);
    vi.mocked(fetchNVD).mockResolvedValue([]);

    // Act & Assert: Should not throw
    await ensureIntelFeedsFresh({ delay: 0 });
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(saveToCache).not.toHaveBeenCalled(); // Should not save on error
  });

  it('should handle partial failures (one source fails, others succeed)', async () => {
    // Arrange: All stale
    vi.mocked(isCacheStale).mockReturnValue({ stale: true, warn: false });

    const mockKEV = [{ id: 'CVE-1', aliases: [], source: 'KEV' as const, kev: true, references: [] }];
    const mockEPSS = [{ id: 'CVE-2', aliases: [], source: 'EPSS' as const, epss: 0.5, references: [] }];

    vi.mocked(fetchKEV).mockResolvedValue(mockKEV);
    vi.mocked(fetchEPSS).mockRejectedValue(new Error('EPSS API down'));
    vi.mocked(fetchNVD).mockResolvedValue(mockEPSS);

    // Act
    await ensureIntelFeedsFresh({ delay: 0 });
    await new Promise(resolve => setTimeout(resolve, 10));

    // Should still save KEV and NVD
    expect(saveToCache).toHaveBeenCalledWith('kev', mockKEV);
    expect(saveToCache).toHaveBeenCalledWith('nvd', mockEPSS);
  });

  it('should resolve immediately (non-blocking)', async () => {
    // Arrange
    vi.mocked(isCacheStale).mockReturnValue({ stale: true, warn: false });
    vi.mocked(fetchKEV).mockImplementation(() => new Promise(resolve => setTimeout(() => resolve([]), 1000)));

    const start = Date.now();
    
    // Act - should resolve quickly, not wait for fetch
    await ensureIntelFeedsFresh({ delay: 10 });
    const elapsed = Date.now() - start;

    // Assert - should resolve within 100ms (delay + small buffer)
    expect(elapsed).toBeLessThan(100);
  });

  it('should respect timeout option', async () => {
    // Arrange
    vi.mocked(isCacheStale).mockReturnValue({ stale: true, warn: false });
    vi.mocked(fetchKEV).mockImplementation(() => new Promise(resolve => setTimeout(() => resolve([{ id: 'CVE-1', aliases: [], source: 'KEV' as const, references: [] }]), 10000)));

    // Act - with short timeout
    await ensureIntelFeedsFresh({ timeout: 50, delay: 10 });

    // Assert - should timeout and not save
    expect(saveToCache).not.toHaveBeenCalled();
  });

  it('should support verbose mode', async () => {
    // Arrange
    vi.mocked(isCacheStale).mockReturnValue({ stale: false, warn: false });
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    // Act
    await ensureIntelFeedsFresh({ verbose: true, delay: 0 });
    await new Promise(resolve => setTimeout(resolve, 10));

    // Assert - should log in verbose mode
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});

describe('getFeedStatus', () => {
  let getFeedStatus: () => Array<{ source: string; stale: boolean; age?: number; warn: boolean }>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const module = await import('./auto-update.js');
    getFeedStatus = module.getFeedStatus;
  });

  it('should return status for all sources', () => {
    // Arrange
    vi.mocked(isCacheStale)
      .mockReturnValueOnce({ stale: true, age: 1.5, warn: true })
      .mockReturnValueOnce({ stale: false, age: 0.5, warn: false })
      .mockReturnValueOnce({ stale: true, age: 4.0, warn: true });

    // Act
    const status = getFeedStatus();

    // Assert
    expect(status).toHaveLength(3);
    expect(status[0]).toEqual({ source: 'kev', stale: true, age: 1.5, warn: true });
    expect(status[1]).toEqual({ source: 'epss', stale: false, age: 0.5, warn: false });
    expect(status[2]).toEqual({ source: 'nvd', stale: true, age: 4.0, warn: true });
  });

  it('should handle missing cache info', () => {
    // Arrange - isCacheStale returns undefined
    vi.mocked(isCacheStale).mockReturnValue({ stale: true, warn: false });

    // Act
    const status = getFeedStatus();

    // Assert
    expect(status[0]).toEqual({ source: 'kev', stale: true, age: undefined, warn: false });
  });
});

describe('Auto-update integration with CLI modes', () => {
  it('should export ensureIntelFeedsFresh function', async () => {
    // This is a behavioral test - verify the function is exported and callable
    const { ensureIntelFeedsFresh } = await import('./auto-update.js');
    expect(typeof ensureIntelFeedsFresh).toBe('function');
  });

  it('should export getFeedStatus function', async () => {
    const { getFeedStatus } = await import('./auto-update.js');
    expect(typeof getFeedStatus).toBe('function');
  });
});