import { describe, it, expect, vi, beforeEach } from 'vitest';

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
  let ensureIntelFeedsFresh: () => Promise<void>;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Re-import to get fresh module with mocks
    const module = await import('./auto-update.js');
    ensureIntelFeedsFresh = module.ensureIntelFeedsFresh;
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

    // Act
    await ensureIntelFeedsFresh();

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
    await ensureIntelFeedsFresh();

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
    await ensureIntelFeedsFresh();

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
    await ensureIntelFeedsFresh();

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
    await ensureIntelFeedsFresh();

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
    await expect(ensureIntelFeedsFresh()).resolves.not.toThrow();
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

    // Act & Assert: Should not throw despite EPSS failure
    await expect(ensureIntelFeedsFresh()).resolves.not.toThrow();

    // Should still save KEV and NVD
    expect(saveToCache).toHaveBeenCalledWith('kev', mockKEV);
    expect(saveToCache).toHaveBeenCalledWith('nvd', mockEPSS);
  });
});

describe('Auto-update integration with CLI modes', () => {
  it('should export ensureIntelFeedsFresh function', async () => {
    // This is a behavioral test - verify the function is exported and callable
    const { ensureIntelFeedsFresh } = await import('./auto-update.js');
    expect(typeof ensureIntelFeedsFresh).toBe('function');
  });
});