# Vulnerability Intelligence Sources

This reference documents the vulnerability intelligence feeds used by skill-audit for dependency vulnerability scanning.

## Overview

skill-audit integrates with five major vulnerability intelligence sources:

| Source | Provider | Update Frequency | Cache Duration |
|--------|----------|-----------------|-----------------|
| CISA KEV | CISA | Daily | 1 day |
| NIST NVD | NIST | Daily | 1 day |
| FIRST EPSS | FIRST | 3-day cycle | 3 days |
| GitHub GHSA | GitHub | On-release | 3 days |
| OSV.dev | Google | On-query | 7 days |

---

## CISA KEV (Known Exploited Vulnerabilities)

### Overview

The CISA Known Exploited Vulnerabilities (KEV) catalog is a list of vulnerabilities that have been exploited in the wild. It is the authoritative source for actively exploited vulnerabilities.

### Details

| Attribute | Value |
|-----------|-------|
| **Full Name** | CISA Known Exploited Vulnerabilities Catalog |
| **Provider** | Cybersecurity and Infrastructure Security Agency (CISA) |
| **URL** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| **API Endpoint** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| **Update Frequency** | Daily (around 14:00 UTC) |
| **Max Cache Age** | 1 day |
| **Warning Threshold** | 3 days |

### Data Format

```json
{
  "cveID": "CVE-2021-44228",
  "vendorProject": "Apache Software Foundation",
  "product": "Apache Log4j",
  "vulnerabilityName": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
  "knownRansomwareCampaignUse": "Known"
}
```

### Usage in skill-audit

- Cross-references skill dependencies against KEV
- Flags any CVEs in dependencies that are actively exploited
- Provides "known ransomware campaign" context in findings

---

## NIST NVD (National Vulnerability Database)

### Overview

The NVD is the U.S. government repository of standards-based vulnerability management data. It provides CVSS scores, CWE mappings, and detailed vulnerability descriptions.

### Details

| Attribute | Value |
|-----------|-------|
| **Full Name** | National Vulnerability Database |
| **Provider** | National Institute of Standards and Technology (NIST) |
| **URL** | https://nvd.nist.gov/ |
| **API Endpoint** | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| **Update Frequency** | Daily (around 00:00 UTC) |
| **Max Cache Age** | 1 day |
| **Warning Threshold** | 3 days |

### Data Format

```json
{
  "id": "CVE-2021-44228",
  "descriptions": [
    {
      "lang": "en",
      "value": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints."
    }
  ],
  "metrics": {
    "cvssMetricV31": [
      {
        "cvssData": {
          "baseScore": 10.0,
          "baseSeverity": "CRITICAL"
        }
      }
    ]
  }
}
```

### Usage in skill-audit

- Provides CVSS scores for severity assessment
- Maps CVEs to CWE (Common Weakness Enumeration)
- Provides detailed descriptions for findings

---

## FIRST EPSS (Exploit Prediction Scoring System)

### Overview

EPSS provides a probability score (0-100) that a vulnerability will be exploited within the next 30 days. It helps prioritize remediation efforts.

### Details

| Attribute | Value |
|-----------|-------|
| **Full Name** | Exploit Prediction Scoring System |
| **Provider** | FIRST (Forum of Incident Response and Security Teams) |
| **URL** | https://www.first.org/epss/ |
| **API Endpoint** | https://api.first.org/data/v1/epss |
| **Update Frequency** | Daily (around 00:00 UTC) |
| **Max Cache Age** | 3 days |
| **Warning Threshold** | 3 days |

### Data Format

```json
{
  "data": [
    {
      "cve": "CVE-2021-44228",
      "epss": 0.97,
      "percentile": 0.9998,
      "date": "2024-01-15"
    }
  ]
}
```

### Usage in skill-audit

- Calculates exploit probability for each CVE
- Prioritizes high-probability exploits in findings
- Helps identify urgent remediation needs

### EPSS Score Interpretation

| Score | Interpretation |
|-------|---------------|
| 0.0 - 0.1 | Very low exploit probability |
| 0.1 - 0.5 | Low exploit probability |
| 0.5 - 0.9 | Moderate exploit probability |
| 0.9 - 1.0 | High exploit probability |

---

## GitHub Security Advisories (GHSA)

### Overview

GitHub Security Advisories provide vulnerability information specific to the open-source ecosystem, including package ecosystem, affected versions, and patches.

### Details

| Attribute | Value |
|-----------|-------|
| **Full Name** | GitHub Security Advisories |
| **Provider** | GitHub |
| **URL** | https://github.com/advisories |
| **API Endpoint** | https://api.github.com/advisories |
| **Update Frequency** | On-release (varies) |
| **Max Cache Age** | 3 days |
| **Warning Threshold** | 3 days |

### Data Format

```json
{
  "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
  "cve_id": "CVE-2021-44228",
  "summary": "Remote code injection in Log4j",
  "severity": "critical",
  "published_at": "2021-12-10T00:00:00Z",
  "vulnerabilities": [
    {
      "package": {
        "ecosystem": "Maven",
        "name": "org.apache.logging.log4j:log4j-core"
      },
      "vulnerable_version_range": "< 2.15.0"
    }
  ]
}
```

### Usage in skill-audit

- Maps vulnerabilities to package ecosystems (npm, pip, Maven, etc.)
- Provides version range information for precise matching
- Includes patched versions in recommendations

---

## OSV.dev (Open Source Vulnerabilities)

### Overview

OSV is an open-source vulnerability database that aggregates vulnerability data from multiple sources and provides a unified API.

### Details

| Attribute | Value |
|-----------|-------|
| **Full Name** | Open Source Vulnerabilities Database |
| **Provider** | Google |
| **URL** | https://osv.dev/ |
| **API Endpoint** | https://api.osv.dev/v1/query |
| **Update Frequency** | On-query (no bulk download) |
| **Max Cache Age** | 7 days |
| **Warning Threshold** | 3 days |

### Data Format

```json
{
  "id": "OSV-2021-1349",
  "summary": "Remote code execution in Log4j",
  "details": "Apache Log4j2 2.0-beta9 through 2.15.0...",
  "aliases": ["CVE-2021-44228"],
  "published": "2021-12-10T00:00:00Z",
  "affected": [
    {
      "package": {
        "name": "org.apache.logging.log4j:log4j-core",
        "ecosystem": "Maven"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {"introduced": "2.0.0"},
            {"fixed": "2.15.0"}
          ]
        }
      ]
    }
  ]
}
```

### Usage in skill-audit

- Queries on-demand for package vulnerabilities
- Supports multiple package ecosystems
- Provides unified vulnerability format

---

## Cache Management

### Cache Location

```
.cache/skill-audit/feeds/
├── kev.json
├── nvd.json
├── epss.json
├── ghsa.json
└── osv.json
```

### Cache Update

```bash
# Manual update
npx skill-audit --update-db

# Update specific sources
npx skill-audit --update-db --source kev epss nvd
```

### Staleness Warnings

When cached data exceeds warning threshold:

```
⚠️ Vulnerability DB is stale (4.2 days for KEV, 5.1 days for EPSS)
   Run: npx skill-audit --update-db
```

---

## Source Prioritization

When multiple sources provide the same CVE:

| Priority | Source | Use Case |
|----------|--------|----------|
| 1 | CISA KEV | Actively exploited vulnerabilities |
| 2 | GHSA | Package-specific details |
| 3 | NVD | CVSS scores, CWE mappings |
| 4 | EPSS | Exploit probability |
| 5 | OSV | Additional ecosystem coverage |

---

## API Rate Limits

| Source | Rate Limit | Notes |
|--------|------------|-------|
| CISA KEV | None | Public dataset |
| NIST NVD | 6 requests/rolling 30s | Requires API key for higher limits |
| FIRST EPSS | 100 requests/day | Public API |
| GitHub GHSA | 5000 requests/hour | Requires authentication for higher limits |
| OSV.dev | 10000 requests/day | Public API |

---

## References

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NIST NVD](https://nvd.nist.gov/)
- [FIRST EPSS](https://www.first.org/epss/)
- [GitHub Security Advisories](https://github.com/advisories)
- [OSV.dev](https://osv.dev/)