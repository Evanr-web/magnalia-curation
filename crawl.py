#!/usr/bin/env python3
"""
Magnalia Letter — Weekly Content Crawl & Scoring Pipeline

Crawls RSS feeds, YouTube channels, and podcasts defined in sources.json.
Validates links, checks security, scores relevance via AI, and outputs
a weekly digest JSON for the Curation Board.

Usage:
    python3 crawl.py                    # Full crawl + generate digest
    python3 crawl.py --dry-run          # Crawl but don't write/push
    python3 crawl.py --validate-only    # Just validate existing digest links
    python3 crawl.py --test-sources     # Test all source feeds are reachable

Requires:
    pip install feedparser requests anthropic
    
Environment:
    ANTHROPIC_API_KEY    — for AI scoring
    SAFE_BROWSING_KEY    — Google Safe Browsing API key (optional, skipped if missing)
"""

import json
import os
import sys
import ssl
import hashlib
import argparse
import subprocess
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import feedparser
import requests
from anthropic import Anthropic

# ============================================
# CONFIG
# ============================================
SOURCES_FILE = os.path.join(os.path.dirname(__file__), 'sources.json')
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
BLOCKLIST_FILE = os.path.join(os.path.dirname(__file__), 'blocklist.json')

LOOKBACK_DAYS = 7
MAX_ITEMS = 20
MIN_SCORE = 5
REQUEST_TIMEOUT = 15
MAX_REDIRECTS = 3
USER_AGENT = 'MagnaliaCrawler/1.0 (gregorythegreat.ca; content curation)'

# ============================================
# HELPERS
# ============================================
def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default if default is not None else {}


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  → Saved {path}")


def make_id(source_name, title):
    slug = title.lower()[:60].replace(' ', '-')
    slug = ''.join(c for c in slug if c.isalnum() or c == '-')
    prefix = source_name.lower().replace(' ', '-')[:20]
    return f"{prefix}-{slug}-{hashlib.md5(title.encode()).hexdigest()[:6]}"


def is_within_lookback(date_str, days=LOOKBACK_DAYS):
    """Check if a date string is within the lookback window."""
    if not date_str:
        return False
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
    except Exception:
        try:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            return True  # If we can't parse, include it
    
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt >= cutoff


def extract_date(entry):
    """Extract publication date from feed entry."""
    for field in ['published', 'updated', 'created']:
        if hasattr(entry, field) and getattr(entry, field):
            return getattr(entry, field)
    return None


def normalize_date(date_str):
    """Normalize date to YYYY-MM-DD."""
    if not date_str:
        return datetime.now().strftime('%Y-%m-%d')
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
        return dt.strftime('%Y-%m-%d')
    except Exception:
        try:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d')
        except Exception:
            return datetime.now().strftime('%Y-%m-%d')


# ============================================
# GATE 1: LINK VALIDATION
# ============================================
def validate_link(url):
    """
    Validate a URL is live, follows redirects safely, and returns HTML.
    Returns (valid: bool, status: int, flags: list, final_url: str)
    """
    flags = []
    
    if not url or not url.startswith('http'):
        return False, 0, ['invalid-url'], url
    
    original_domain = urlparse(url).netloc
    
    try:
        resp = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={'User-Agent': USER_AGENT},
            verify=True
        )
        
        final_url = resp.url
        final_domain = urlparse(final_url).netloc
        status = resp.status_code
        
        # Check redirect domain
        if final_domain != original_domain:
            # Allow www/non-www and http/https redirects
            orig_base = original_domain.replace('www.', '')
            final_base = final_domain.replace('www.', '')
            if orig_base != final_base:
                flags.append('redirect-domain-change')
        
        # Check redirect count
        if len(resp.history) > MAX_REDIRECTS:
            flags.append('excessive-redirects')
        
        if status == 200:
            return True, status, flags, final_url
        elif status in (301, 302, 303, 307, 308):
            # Shouldn't happen with allow_redirects=True, but just in case
            return True, status, flags, final_url
        elif status == 429:
            # Rate limited — retry once
            import time
            time.sleep(30)
            resp2 = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                                   headers={'User-Agent': USER_AGENT}, verify=True)
            if resp2.status_code == 200:
                return True, 200, flags, resp2.url
            return False, resp2.status_code, flags + ['rate-limited'], resp2.url
        else:
            return False, status, flags + [f'http-{status}'], final_url
            
    except requests.exceptions.SSLError:
        return False, 0, ['ssl-error'], url
    except requests.exceptions.Timeout:
        return False, 0, ['timeout'], url
    except requests.exceptions.ConnectionError:
        return False, 0, ['connection-error'], url
    except Exception as e:
        return False, 0, [f'error: {str(e)[:50]}'], url


# ============================================
# GATE 2: SECURITY SCAN
# ============================================
def load_blocklist():
    data = load_json(BLOCKLIST_FILE, {'domains': []})
    return set(data.get('domains', []))


def check_security(url, trust_level='medium'):
    """
    Security checks on a URL/domain.
    Returns (safe: bool, flags: list)
    """
    flags = []
    domain = urlparse(url).netloc.replace('www.', '')
    
    # Check blocklist
    blocklist = load_blocklist()
    if domain in blocklist:
        return False, ['blocklisted']
    
    # Check suspicious URL patterns
    suspicious_patterns = ['?redirect=', 'base64,', '.exe', '.msi', '.bat', '.cmd']
    if any(p in url.lower() for p in suspicious_patterns):
        return False, ['suspicious-url-pattern']
    
    # Google Safe Browsing (if API key available)
    sb_key = os.environ.get('SAFE_BROWSING_KEY')
    if sb_key:
        try:
            sb_resp = requests.post(
                f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={sb_key}',
                json={
                    'client': {'clientId': 'magnalia-crawler', 'clientVersion': '1.0'},
                    'threatInfo': {
                        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': url}]
                    }
                },
                timeout=10
            )
            if sb_resp.status_code == 200:
                matches = sb_resp.json().get('matches', [])
                if matches:
                    return False, ['safe-browsing-flagged']
        except Exception:
            flags.append('safe-browsing-check-failed')
    else:
        # No API key — note it but don't block
        pass
    
    # Domain trust check
    if trust_level == 'low':
        flags.append('low-trust-source')
    
    # SSL check (already done in link validation, but double-check)
    if not url.startswith('https://'):
        flags.append('no-https')
    
    return True, flags


# ============================================
# GATE 3: AI RELEVANCE SCORING
# ============================================
def score_items_batch(items):
    """
    Score a batch of items using Claude for relevance to GGI's mission.
    Returns items with 'score' field populated.
    """
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        print("  ⚠ No ANTHROPIC_API_KEY — assigning default scores based on source trust")
        for item in items:
            item['score'] = 7 if item.get('_trust') == 'high' else 5
        return items
    
    client = Anthropic(api_key=api_key)
    
    # Batch items into groups of 10 for efficiency
    batch_size = 10
    for i in range(0, len(items), batch_size):
        batch = items[i:i+batch_size]
        
        items_text = "\n\n".join([
            f"ITEM {j+1}:\n"
            f"Title: {item['title']}\n"
            f"Source: {item['source']}\n"
            f"Category: {item['category']}\n"
            f"Summary: {item.get('summary', item.get('_raw_summary', 'No summary available'))}\n"
            f"Tags: {', '.join(item.get('tags', []))}"
            for j, item in enumerate(batch)
        ])
        
        prompt = f"""You are scoring content for the Magnalia Letter, a monthly curated newsletter 
from the Gregory the Great Institute — a Canadian Catholic non-profit dedicated to cultural renewal 
through formation, courses, and publications.

Score each item from 1-10 based on:
- Canadian relevance (+3 if about Catholic life in Canada, +1 if applicable to Canada)
- Intellectual depth (+2 for substantive analysis, -1 for listicles/hot takes)
- Mission alignment (+2 for faith + reason + culture, Catholic intellectual tradition)
- Timeliness (+1 if newsworthy or seasonal)
- Source credibility (+1 for established publications)
- GGI connection (+1 bonus if connects to GGI themes: classical education, Great Books, 
  cultural renewal, liturgy, beauty, community formation, Canadian Catholic life)

Also provide a 1-2 sentence summary suitable for the curation board, and note any 
GGI connection (mention of GGI people, themes, programs, or related work).

{items_text}

Respond in JSON format:
[
  {{"item": 1, "score": 8, "summary": "...", "ggiConnection": "..." or ""}},
  ...
]

Only return the JSON array, nothing else."""

        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Parse response
            text = response.content[0].text.strip()
            # Handle potential markdown code blocks
            if text.startswith('```'):
                text = text.split('\n', 1)[1].rsplit('```', 1)[0]
            
            scores = json.loads(text)
            
            for score_data in scores:
                idx = score_data['item'] - 1
                if 0 <= idx < len(batch):
                    batch[idx]['score'] = score_data.get('score', 5)
                    batch[idx]['summary'] = score_data.get('summary', batch[idx].get('summary', ''))
                    if score_data.get('ggiConnection'):
                        batch[idx]['ggiConnection'] = score_data['ggiConnection']
                        
        except Exception as e:
            print(f"  ⚠ AI scoring failed for batch: {e}")
            for item in batch:
                item['score'] = 6  # Default middle score
    
    return items


# ============================================
# FEED CRAWLING
# ============================================
def crawl_feed_rss(source):
    """Crawl an RSS/Atom feed using feedparser."""
    items = []
    feed = feedparser.parse(source['url'], agent=USER_AGENT)
    
    if feed.bozo and not feed.entries:
        # Try fallback via requests (feedparser's SSL can fail)
        return crawl_feed_requests(source)
    
    for entry in feed.entries:
        pub_date = extract_date(entry)
        if not is_within_lookback(pub_date):
            continue
        
        title = entry.get('title', '').strip()
        link = entry.get('link', '').strip()
        
        if not title or not link:
            continue
        
        summary = ''
        import re
        if hasattr(entry, 'summary') and entry.summary:
            summary = re.sub(r'<[^>]+>', '', entry.summary).strip()[:500]
        elif hasattr(entry, 'description') and entry.description:
            summary = re.sub(r'<[^>]+>', '', entry.description).strip()[:500]
        
        items.append(_make_item(source, title, link, pub_date, summary))
    
    return items


def crawl_feed_requests(source):
    """Fallback: fetch feed via requests and parse XML directly."""
    import xml.etree.ElementTree as ET
    items = []
    
    try:
        resp = requests.get(source['url'], timeout=REQUEST_TIMEOUT,
                           headers={'User-Agent': USER_AGENT})
        if resp.status_code != 200:
            print(f"    ⚠ HTTP {resp.status_code}")
            return []
        
        root = ET.fromstring(resp.text[:100000])
        ns = {'atom': 'http://www.w3.org/2005/Atom'}
        
        # Try Atom entries first, then RSS items
        entries = root.findall('.//atom:entry', ns)
        if entries:
            for entry in entries:
                title_el = entry.find('atom:title', ns)
                link_el = entry.find('atom:link', ns)
                pub_el = entry.find('atom:published', ns) or entry.find('atom:updated', ns)
                summary_el = entry.find('atom:summary', ns) or entry.find('atom:content', ns)
                
                title = title_el.text.strip() if title_el is not None and title_el.text else ''
                link = link_el.get('href', '') if link_el is not None else ''
                pub_date = pub_el.text if pub_el is not None else None
                import re
                summary = re.sub(r'<[^>]+>', '', summary_el.text or '').strip()[:500] if summary_el is not None and summary_el.text else ''
                
                if not title or not link:
                    continue
                if not is_within_lookback(pub_date):
                    continue
                    
                items.append(_make_item(source, title, link, pub_date, summary))
        else:
            # RSS format
            for item_el in root.findall('.//item'):
                title_el = item_el.find('title')
                link_el = item_el.find('link')
                pub_el = item_el.find('pubDate')
                desc_el = item_el.find('description')
                
                title = title_el.text.strip() if title_el is not None and title_el.text else ''
                link = link_el.text.strip() if link_el is not None and link_el.text else ''
                pub_date = pub_el.text if pub_el is not None else None
                import re
                summary = re.sub(r'<[^>]+>', '', desc_el.text or '').strip()[:500] if desc_el is not None and desc_el.text else ''
                
                if not title or not link:
                    continue
                if not is_within_lookback(pub_date):
                    continue
                    
                items.append(_make_item(source, title, link, pub_date, summary))
                
    except Exception as e:
        print(f"    ⚠ Requests fallback failed: {e}")
    
    return items


def _make_item(source, title, link, pub_date, summary):
    """Create a candidate item dict."""
    return {
        'id': make_id(source['name'], title),
        'category': source['category'],
        'title': title,
        'source': source['name'],
        'date': normalize_date(pub_date),
        'url': link,
        '_raw_summary': summary,
        'summary': '',
        'score': 0,
        'tags': list(source.get('tags', [])),
        'ggiConnection': '',
        '_trust': source.get('trust', 'medium'),
        'validated': False,
        'flags': []
    }


def crawl_feed(source):
    """Crawl a single feed and return candidate items."""
    print(f"  Crawling: {source['name']}...")
    
    try:
        if source.get('type') in ('youtube-atom',):
            # YouTube Atom feeds — always use requests (feedparser SSL issues)
            items = crawl_feed_requests(source)
        else:
            items = crawl_feed_rss(source)
    except Exception as e:
        print(f"    ✗ Failed: {e}")
        items = []
    
    print(f"    Found {len(items)} items in lookback window")
    return items


def crawl_all_sources():
    """Crawl all sources and return raw candidate items."""
    sources = load_json(SOURCES_FILE, {'feeds': []})
    all_items = []
    
    print(f"\n📡 Crawling {len(sources['feeds'])} sources...")
    
    for source in sources['feeds']:
        items = crawl_feed(source)
        all_items.extend(items)
    
    print(f"\n📊 Total candidates: {len(all_items)}")
    return all_items


# ============================================
# PIPELINE
# ============================================
def run_pipeline(dry_run=False):
    """Full crawl → validate → score → generate digest."""
    
    print("=" * 60)
    print("MAGNALIA LETTER — WEEKLY CONTENT CRAWL")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M %Z')}")
    print("=" * 60)
    
    # Step 1: Crawl
    candidates = crawl_all_sources()
    
    if not candidates:
        print("\n⚠ No candidates found. Check source feeds.")
        return
    
    # Step 2: Deduplicate by URL
    seen_urls = set()
    unique = []
    for item in candidates:
        if item['url'] not in seen_urls:
            seen_urls.add(item['url'])
            unique.append(item)
    print(f"\n🔍 After dedup: {len(unique)} unique items")
    
    # Step 3: Link validation (Gate 1)
    print("\n🔗 Validating links...")
    validated = []
    rejected_links = 0
    for item in unique:
        # High-trust sources skip link validation (some block bots but are safe)
        if item.get('_trust') == 'high':
            item['validated'] = True
            item['flags'].append('trust-skip-linkcheck')
            validated.append(item)
            continue
        
        valid, status, flags, final_url = validate_link(item['url'])
        if valid:
            item['validated'] = True
            item['url'] = final_url  # Use final URL after redirects
            item['flags'].extend(flags)
            validated.append(item)
        else:
            rejected_links += 1
            if not dry_run:
                print(f"    ✗ Rejected (link): {item['title'][:50]}... → {flags}")
    
    print(f"  ✓ {len(validated)} valid, ✗ {rejected_links} rejected")
    
    # Step 4: Security scan (Gate 2)
    print("\n🛡️ Security scan...")
    secure = []
    rejected_security = 0
    for item in validated:
        safe, sec_flags = check_security(item['url'], item.get('_trust', 'medium'))
        if safe:
            item['flags'].extend(sec_flags)
            secure.append(item)
        else:
            rejected_security += 1
            if not dry_run:
                print(f"    ✗ Rejected (security): {item['title'][:50]}... → {sec_flags}")
    
    print(f"  ✓ {len(secure)} safe, ✗ {rejected_security} rejected")
    
    # Step 5: AI scoring (Gate 3)
    print("\n🧠 AI scoring...")
    scored = score_items_batch(secure)
    
    # Filter by minimum score
    above_threshold = [i for i in scored if i['score'] >= MIN_SCORE]
    below_threshold = [i for i in scored if i['score'] < MIN_SCORE]
    print(f"  ✓ {len(above_threshold)} above threshold (≥{MIN_SCORE}), {len(below_threshold)} below")
    
    # Step 6: Sort and take top N
    above_threshold.sort(key=lambda x: x['score'], reverse=True)
    final_items = above_threshold[:MAX_ITEMS]
    
    # Clean up internal fields
    for item in final_items:
        item.pop('_trust', None)
        item.pop('_raw_summary', None)
        # Strip internal-only flags from output (keep user-facing ones)
        item['flags'] = [f for f in item.get('flags', []) if not f.startswith('trust-skip-')]
        # Add validation metadata
        item['validatedAt'] = datetime.now(timezone.utc).isoformat()
    
    # Step 7: Generate digest
    today = datetime.now()
    # Find next Monday for the digest week label
    days_until_monday = (7 - today.weekday()) % 7
    if days_until_monday == 0:
        days_until_monday = 7
    next_monday = today + timedelta(days=days_until_monday)
    week_label = next_monday.strftime('%Y-%m-%d')
    
    digest = {
        'week': week_label,
        'generated': datetime.now(timezone.utc).isoformat(),
        'itemCount': len(final_items),
        'crawlStats': {
            'sourcesChecked': len(load_json(SOURCES_FILE, {'feeds': []})['feeds']),
            'candidatesFound': len(candidates),
            'afterDedup': len(unique),
            'rejectedLinks': rejected_links,
            'rejectedSecurity': rejected_security,
            'belowScoreThreshold': len(below_threshold),
            'finalItems': len(final_items)
        },
        'items': final_items
    }
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"📋 DIGEST: Week of {week_label}")
    print(f"   {len(final_items)} items from {digest['crawlStats']['sourcesChecked']} sources")
    print("=" * 60)
    
    for item in final_items:
        flags_str = f" ⚠ {', '.join(item['flags'])}" if item['flags'] else ""
        print(f"  [{item['score']:2d}] {item['category']:6s} | {item['title'][:55]}...{flags_str}")
    
    if dry_run:
        print("\n🏃 Dry run — not writing files or pushing")
        return digest
    
    # Save digest
    digest_path = os.path.join(DATA_DIR, f"{week_label}.json")
    save_json(digest_path, digest)
    
    # Also save as 'latest.json' symlink/copy for the board
    latest_path = os.path.join(DATA_DIR, 'latest.json')
    save_json(latest_path, digest)
    
    print(f"\n✅ Digest saved to {digest_path}")
    return digest


def test_sources():
    """Test all source feeds are reachable and returning entries."""
    sources = load_json(SOURCES_FILE, {'feeds': []})
    
    print(f"\n🧪 Testing {len(sources['feeds'])} sources...\n")
    
    ok = 0
    fail = 0
    
    for source in sources['feeds']:
        try:
            feed = feedparser.parse(source['url'], agent=USER_AGENT)
            entry_count = len(feed.entries)
            if entry_count > 0:
                latest = feed.entries[0].get('title', 'No title')[:60]
                print(f"  ✓ {source['name']:35s} | {entry_count:3d} entries | Latest: {latest}")
                ok += 1
            elif feed.bozo:
                print(f"  ✗ {source['name']:35s} | Feed error: {str(feed.bozo_exception)[:50]}")
                fail += 1
            else:
                print(f"  ⚠ {source['name']:35s} | 0 entries (feed may be empty)")
                ok += 1
        except Exception as e:
            print(f"  ✗ {source['name']:35s} | {str(e)[:50]}")
            fail += 1
    
    print(f"\n📊 Results: {ok} OK, {fail} failed out of {len(sources['feeds'])} sources")


def validate_existing():
    """Validate links in the most recent digest."""
    latest_path = os.path.join(DATA_DIR, 'latest.json')
    if not os.path.exists(latest_path):
        # Find most recent data file
        files = sorted([f for f in os.listdir(DATA_DIR) if f.endswith('.json') and f != 'latest.json'])
        if not files:
            print("No digest files found.")
            return
        latest_path = os.path.join(DATA_DIR, files[-1])
    
    data = load_json(latest_path)
    items = data.get('items', [])
    
    print(f"\n🔗 Validating {len(items)} links in {latest_path}...\n")
    
    ok = 0
    broken = 0
    
    for item in items:
        valid, status, flags, final_url = validate_link(item['url'])
        if valid:
            print(f"  ✓ {status} | {item['title'][:60]}")
            ok += 1
        else:
            print(f"  ✗ {flags} | {item['title'][:60]}")
            print(f"       URL: {item['url']}")
            broken += 1
    
    print(f"\n📊 Results: {ok} OK, {broken} broken out of {len(items)} links")


# ============================================
# CLI
# ============================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Magnalia Letter content crawl pipeline')
    parser.add_argument('--dry-run', action='store_true', help='Crawl without writing files')
    parser.add_argument('--validate-only', action='store_true', help='Validate existing digest links')
    parser.add_argument('--test-sources', action='store_true', help='Test all source feeds')
    args = parser.parse_args()
    
    if args.test_sources:
        test_sources()
    elif args.validate_only:
        validate_existing()
    else:
        run_pipeline(dry_run=args.dry_run)
