# Crawl Pipeline — Validation & Security Spec

## Overview

Every item that appears on the Curation Board must pass three gates before it's included in the weekly digest:

1. **Link Validation** — URL is live and returns 200
2. **Security Scan** — domain is safe and not compromised
3. **Content Relevance** — AI scoring passes threshold

No item reaches the board without passing all three.

---

## Gate 1: Link Validation

Every URL is tested before inclusion:

```
For each candidate item:
  1. HTTP HEAD request with 10s timeout
  2. Accept: 200, 301, 302 (follow redirects, max 3)
  3. Reject: 404, 410, 500, 503, timeouts, connection errors
  4. Reject: SSL certificate errors (expired, self-signed, mismatched)
  5. Final URL after redirects must still be on the expected domain
     (prevents redirect hijacking: firstthings.com → malware.xyz)
```

**Retry logic:** If a URL fails with a transient error (429, 503, timeout), retry once after 30 seconds. If it fails again, exclude it.

**Redirect domain check:** If the final URL domain differs from the original domain, flag it for manual review rather than auto-including. Legitimate redirects (www → non-www, http → https) are allowed.

---

## Gate 2: Security Scan

Before any URL is included, check the domain against known threat databases:

### Checks performed:
1. **Google Safe Browsing API** — checks if the domain is flagged for malware, phishing, or unwanted software
2. **Domain age check** — domains registered less than 30 days ago are flagged for review (not auto-rejected, since legitimate new sites exist)
3. **SSL certificate validation** — must have valid, non-expired SSL certificate from a recognized CA
4. **Known-good allowlist** — sources in `sources.json` are pre-approved and skip the domain age check (they've been manually vetted)
5. **Content-Type check** — response must be `text/html` or `application/xhtml+xml` (not a binary download, executable, etc.)

### Red flags (auto-reject):
- Domain flagged by Google Safe Browsing
- SSL certificate invalid, expired, or self-signed
- Response Content-Type is binary/executable
- URL contains suspicious patterns: `?redirect=`, base64-encoded paths, known phishing TLDs
- Domain on manual blocklist (`blocklist.json`)

### Yellow flags (include but mark for review):
- Domain not in sources.json (new/unknown source)
- Domain registered < 90 days ago
- Redirect to a different domain
- Multiple redirects (>2)

Items with yellow flags appear on the board with a small ⚠ indicator so the reviewer is aware.

---

## Gate 3: Content Relevance Scoring

After validation, content is scored by AI for relevance to GGI's mission:

### Scoring rubric (1-10):

| Factor | Weight | Description |
|--------|--------|-------------|
| Canadian relevance | +3 | Content about Catholic life in Canada specifically |
| Applicable to Canada | +1 | Not Canadian but applicable to the Canadian context |
| Intellectual depth | +2 | Substantive analysis, not listicles or hot takes |
| Mission alignment | +2 | Faith + reason + culture, Catholic intellectual tradition |
| Timeliness | +1 | Published within the last 7 days |
| Source credibility | +1 | Established publication with editorial standards |
| GGI connection | +1 (bonus) | Mentions GGI people, themes, programs, or books |

**Threshold:** Items scoring 5+ are included in the digest. Items scoring 3-4 are held in reserve (available if the week is thin). Items below 3 are discarded.

---

## Source Management

### sources.json structure:
```json
{
  "feeds": [
    {
      "name": "First Things",
      "url": "https://www.firstthings.com/rss",
      "type": "rss",
      "category": "read",
      "trust": "high",
      "tags": ["catholic-intellectual", "culture"]
    },
    {
      "name": "Brian Holdsworth",
      "url": "https://www.youtube.com/feeds/videos.xml?channel_id=UCkV76QLnMFljbbAS3W13C7g",
      "type": "youtube-rss",
      "category": "watch",
      "trust": "high",
      "tags": ["catholic", "beauty", "ggi-board-member"]
    }
  ]
}
```

### Trust levels:
- **high** — editorially vetted publications, known Catholic outlets. Skip domain age check.
- **medium** — personal blogs, smaller outlets. Full security scan.
- **low** — discovered via links/shares, not yet vetted. Full scan + yellow flag on board.

### Adding new sources:
New sources can be added to `sources.json` via PR or by the crawl pipeline when it discovers frequently-cited domains. New sources start at `trust: "low"` and are promoted after manual review.

---

## Blocklist

`blocklist.json` contains domains that should never appear on the board:

```json
{
  "domains": [
    "example-malware-site.com"
  ],
  "reason": {
    "example-malware-site.com": "Flagged by Safe Browsing 2026-04"
  }
}
```

Updated manually or automatically when a domain fails Safe Browsing checks.

---

## Weekly Crawl Sequence

```
Sunday 11:00 PM MST:

1. Load sources.json
2. For each source:
   a. Fetch RSS/API feed
   b. Extract items published in last 7 days
   c. For each item URL:
      - Gate 1: Link validation (HEAD request + redirect check)
      - Gate 2: Security scan (Safe Browsing + SSL + domain checks)
      - Gate 3: Content scoring (AI relevance)
   d. Items passing all gates → candidate list
3. Sort candidates by score (descending)
4. Take top 15-20 items
5. Generate data/YYYY-MM-DD.json
6. Include validation metadata in each item:
   {
     "validated": true,
     "validatedAt": "2026-05-04T05:00:00Z",
     "httpStatus": 200,
     "sslValid": true,
     "safeBrowsing": "clean",
     "flags": []
   }
7. Commit and push to repo
8. Send notification email: "This week's digest is ready for review"
```

---

## Monitoring

- **Weekly report** includes: sources checked, items found, items rejected (with reasons), items included
- **Alert on:** any high-trust source returning errors (site may be down or compromised)
- **Quarterly:** review source list, add/remove sources, promote trust levels
