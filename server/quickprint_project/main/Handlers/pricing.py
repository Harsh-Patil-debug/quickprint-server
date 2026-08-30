# pricing.py
# THE server-side source of truth for what a print job costs — ported line-for-line from
# quickprint-hub/src/lib/quickprint.ts's PAPERS/ADDONS/CONVENIENCE_FEE/parseRange/
# priceOrder. The frontend keeps its own copy of this exact same logic for the live
# preview while configuring a job; this is what actually gets charged and verified at
# order-creation time, using the server's own page_count (never the client's) — same
# "never trust client price" principle used for every pricing flow built this session.

import re

PAPERS = {
    "a4-75": {"label": "A4 · 75 GSM", "multiplier": 1, "note": "Everyday standard"},
    "a4-100": {"label": "A4 · 100 GSM", "multiplier": 1.4, "note": "Premium bond"},
    "a3": {"label": "A3 Sheet", "multiplier": 2.2, "note": "Posters & charts"},
}
DEFAULT_PAPER_ID = "a4-75"

ADDONS = {
    "staple": {"label": "Stapling", "price": 2, "hint": "Top-left corner staple"},
    "clip": {"label": "Corner Clip", "price": 5, "hint": "Metal clip binding"},
    "spiral": {"label": "Spiral Binding", "price": 30, "hint": "Plastic coil + cover"},
}

CONVENIENCE_FEE = 3

_RANGE_PART_RE = re.compile(r"^(\d+)\s*-\s*(\d+)$")


def parse_range(range_str: str, max_pages: int) -> list[int]:
    """Ported verbatim from quickprint.ts's parseRange — 'a-b, c' style syntax,
    clamped to [1, max_pages], deduped, sorted ascending."""
    out = set()
    for chunk in (range_str or "").split(","):
        part = chunk.strip()
        if not part:
            continue
        m = _RANGE_PART_RE.match(part)
        if m:
            a = max(1, int(m.group(1)))
            b = min(max_pages, int(m.group(2)))
            for i in range(a, b + 1):
                out.add(i)
        elif part.isdigit():
            n = int(part)
            if 1 <= n <= max_pages:
                out.add(n)
    return sorted(out)


def price_order(cfg: dict, shop: dict) -> dict:
    """
    cfg: {page_count, color ('bw'|'color'), duplex (bool), paper (id), range_mode
    ('all'|'custom'), custom_range (str), copies (int), addons (list[str])}
    shop: needs rateBW/rateColor (or rate_bw/rate_color — both read for convenience
    across the raw-doc vs API-shape callers).
    """
    page_count = int(cfg.get("page_count", 0) or 0)
    if cfg.get("range_mode") == "all":
        selected = page_count
    else:
        selected = len(parse_range(cfg.get("custom_range", ""), page_count))

    paper = PAPERS.get(cfg.get("paper"), PAPERS[DEFAULT_PAPER_ID])
    rate_bw = shop.get("rateBW", shop.get("rate_bw", 0))
    rate_color = shop.get("rateColor", shop.get("rate_color", 0))
    base_rate = rate_color if cfg.get("color") == "color" else rate_bw
    rate = base_rate * paper["multiplier"]

    copies = max(1, int(cfg.get("copies", 1) or 1))
    printed_pages = selected * copies
    sheets = -(-printed_pages // 2) if cfg.get("duplex") else printed_pages  # ceil div
    page_cost = printed_pages * rate
    duplex_saving = page_cost * 0.1 if cfg.get("duplex") else 0

    addon_ids = cfg.get("addons") or []
    addon_unit_cost = sum(ADDONS[a]["price"] for a in addon_ids if a in ADDONS)
    addon_cost = addon_unit_cost * copies

    subtotal = page_cost - duplex_saving + addon_cost
    total = subtotal + CONVENIENCE_FEE

    return {
        "selected": selected,
        "printed_pages": printed_pages,
        "sheets": sheets,
        "rate": round(rate, 4),
        "page_cost": round(page_cost, 2),
        "duplex_saving": round(duplex_saving, 2),
        "addon_cost": round(addon_cost, 2),
        "subtotal": round(subtotal, 2),
        "total": round(total, 2),
    }
