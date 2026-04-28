# Magnalia Letter — Curation Board

A content review tool for the Gregory the Great Institute's Magnalia Letter.

## How It Works

1. **Weekly crawl** generates a `data/YYYY-MM-DD.json` file with 15-20 curated items
2. **Dr. Topping** opens the board, reads articles, and selects items for the Letter
3. **Selections** are sent to Victor (via API or email fallback) for inclusion in the monthly Magnalia Letter

## For Reviewers (Dr. Topping)

1. Open the link you received
2. Browse the cards — click "Read Article" to open items in a new tab
3. Click the **+** button on items you want in the Letter
4. When done, click **"Send Selections to Victor"**
5. That's it!

## Technical Setup

### Local Development
```bash
# Serve locally
npx serve .
```

### Data Format
Weekly digest files go in `data/YYYY-MM-DD.json`. See `data/sample-2026-05-04.json` for the schema.

### Submit Endpoint
The submit button POSTs to `./api/submit`. This should be a Cloudflare Function (or similar) that:
1. Commits selections to `selections/YYYY-MM-DD.json` in this repo
2. Sends a formatted email to Victor at vcarpay@gregorythegreat.ca

If the endpoint isn't configured, the UI falls back to a mailto: link.

### Automated Digest Generation
A weekly cron job (Sunday night MST) will:
1. Crawl all monitored RSS feeds, YouTube channels, and podcast feeds
2. Score items by relevance to GGI's mission
3. Generate the weekly JSON file
4. Push to this repo (triggers GitHub Pages rebuild)
5. Send a notification email to Dr. Topping

## Sources

See `sources.json` for the full list of monitored feeds.
