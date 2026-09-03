# shops.py
# Print-shop directory + hyperlocal search. Haversine formula ported directly from
# khelomore-server/.../Handlers/cafes.py's calculate_haversine_distance — this replaces
# quickprint-hub's prototype fake x/y-percentage "map" positions and fake radius filter
# with real geography.

import math
from bson import ObjectId
from .db_connection import db_main

# Migrated from quickprint-hub/src/lib/quickprint.ts's hardcoded SHOPS array — same
# names/rates/capabilities, now with real (approximate) lat/lng instead of fake x/y
# percentages, seeded once via seed_shops_handler().
SEED_SHOPS = [
    {
        "name": "NexaPrint Xerox Hub", "area": "Gate 2, Engineering Block",
        "address": "Shop 4, Gate 2 Market, Engineering Block, Viman Nagar",
        "phone": "+91 98220 41102", "lat": 18.5679, "lng": 73.9143,
        "rate_bw": 1.0, "rate_color": 6, "color": True, "spiral": True, "open24": True,
        "hours": "Open 24 hours", "rating": 4.8,
        "image_urls": ["https://res.cloudinary.com/dx1ulvuqy/image/upload/v1787860911/quickprint/shops/zzvlnfslwcvypdcfdsan.jpg"],
    },
    {
        "name": "CampusStation Copy Point", "area": "Central Library Lane",
        "address": "12A Library Lane, opposite Central Reading Hall",
        "phone": "+91 99700 33821", "lat": 18.5700, "lng": 73.9100,
        "rate_bw": 0.9, "rate_color": 5, "color": True, "spiral": True, "open24": False,
        "hours": "8:00 AM – 11:00 PM", "rating": 4.6,
        "image_urls": ["https://res.cloudinary.com/dx1ulvuqy/image/upload/v1787860913/quickprint/shops/kfrnpkywfeea0nt9qwsi.jpg"],
    },
    {
        "name": "SwiftKopy Express", "area": "Hostel C Arcade",
        "address": "Kiosk 2, Hostel C Arcade, North Campus",
        "phone": "+91 91450 77219", "lat": 18.5650, "lng": 73.9160,
        "rate_bw": 1.2, "rate_color": 7, "color": False, "spiral": False, "open24": False,
        "hours": "9:00 AM – 10:00 PM", "rating": 4.4,
        "image_urls": ["https://res.cloudinary.com/dx1ulvuqy/image/upload/v1787860913/quickprint/shops/g2tkzndkvorsvk4dtlhd.jpg"],
    },
    {
        "name": "InkPost Business Centre", "area": "Tech Park Tower B",
        "address": "Ground Floor, Tower B, Magarpatta Tech Park",
        "phone": "+91 98501 26644", "lat": 18.5158, "lng": 73.9315,
        "rate_bw": 1.5, "rate_color": 8, "color": True, "spiral": True, "open24": False,
        "hours": "7:00 AM – 9:00 PM", "rating": 4.9,
        "image_urls": ["https://res.cloudinary.com/dx1ulvuqy/image/upload/v1787860914/quickprint/shops/v8m6qaeuvcfscf7ujblr.jpg"],
    },
    {
        "name": "PrintDrop Corner", "area": "Metro Station Exit 3",
        "address": "Kiosk 9, Metro Exit 3 Concourse",
        "phone": "+91 90040 51188", "lat": 18.5550, "lng": 73.9200,
        "rate_bw": 1.1, "rate_color": 6.5, "color": True, "spiral": False, "open24": True,
        "hours": "Open 24 hours", "rating": 4.2,
        "image_urls": ["https://res.cloudinary.com/dx1ulvuqy/image/upload/v1787860915/quickprint/shops/sfos3pxvyssa4iksrgoc.jpg"],
    },
]

# A shop shows "busy" once its live queue (jobs actually waiting to be printed) crosses
# this depth — matches the spirit of the prototype's per-shop hardcoded queueJobs/status.
BUSY_QUEUE_THRESHOLD = 3
# Rough per-job wait estimate for the "waitMins" display field — real per-shop timing
# data doesn't exist yet, so this is a simple, honest placeholder (not fabricated
# precision) until shops start reporting real print durations.
MINUTES_PER_QUEUED_JOB = 3


def calculate_haversine_distance(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points on Earth in kilometers. Ported
    verbatim from khelomore-server/.../Handlers/cafes.py."""
    try:
        lat1, lon1, lat2, lon2 = map(math.radians, [float(lat1), float(lon1), float(lat2), float(lon2)])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        c = 2 * math.asin(math.sqrt(a))
        r = 6371.0
        return round(c * r, 2)
    except Exception:
        return None


def _queue_depth(shop_id: str) -> int:
    return db_main.orders.count_documents({"shop_id": shop_id, "status": {"$in": ["queued", "printing"]}})


def map_shop_doc(doc, user_lat=None, user_lon=None):
    shop_id = str(doc["_id"])
    queue_jobs = _queue_depth(shop_id)
    distance_km = None
    if user_lat is not None and user_lon is not None:
        distance_km = calculate_haversine_distance(user_lat, user_lon, doc.get("lat"), doc.get("lng"))
    return {
        "id": shop_id,
        "name": doc.get("name", ""),
        "area": doc.get("area", ""),
        "address": doc.get("address", ""),
        "phone": doc.get("phone", ""),
        "imageUrls": doc.get("image_urls") or [],
        "lat": doc.get("lat"),
        "lng": doc.get("lng"),
        "distanceKm": distance_km,
        "rateBW": doc.get("rate_bw", 0),
        "rateColor": doc.get("rate_color", 0),
        "queueJobs": queue_jobs,
        "waitMins": queue_jobs * MINUTES_PER_QUEUED_JOB,
        "status": "busy" if queue_jobs >= BUSY_QUEUE_THRESHOLD else "ready",
        "color": bool(doc.get("color", False)),
        "spiral": bool(doc.get("spiral", False)),
        "open24": bool(doc.get("open24", False)),
        "hours": doc.get("hours", ""),
        "rating": doc.get("rating", 0),
        "isActive": doc.get("is_active", True),
    }


def get_shops_handler(lat=None, lng=None, radius_km=None, color=None, spiral=None, open24=None, sort="distance"):
    query = {"is_active": {"$ne": False}}
    if color:
        query["color"] = True
    if spiral:
        query["spiral"] = True
    if open24:
        query["open24"] = True

    docs = list(db_main.shops.find(query))
    user_lat = float(lat) if lat not in (None, "") else None
    user_lng = float(lng) if lng not in (None, "") else None

    shops = [map_shop_doc(d, user_lat, user_lng) for d in docs]

    if radius_km is not None and user_lat is not None:
        radius = float(radius_km)
        shops = [s for s in shops if s["distanceKm"] is not None and s["distanceKm"] <= radius]

    if sort == "queue":
        shops.sort(key=lambda s: s["waitMins"])
    elif sort == "price":
        shops.sort(key=lambda s: s["rateBW"])
    elif user_lat is not None:
        shops.sort(key=lambda s: s["distanceKm"] if s["distanceKm"] is not None else float("inf"))

    return {"status": 200, "shops": shops}


def get_shop_by_id_handler(shop_id, lat=None, lng=None):
    if not ObjectId.is_valid(shop_id):
        return {"status": 404, "error": "Shop not found."}
    doc = db_main.shops.find_one({"_id": ObjectId(shop_id)})
    if not doc:
        return {"status": 404, "error": "Shop not found."}
    user_lat = float(lat) if lat not in (None, "") else None
    user_lng = float(lng) if lng not in (None, "") else None
    return {"status": 200, "shop": map_shop_doc(doc, user_lat, user_lng)}


def map_shop_doc_admin(doc):
    """Superset of map_shop_doc for the super-admin panel — includes fields a public
    customer never needs (owner contact, city/state, website/instagram, notes,
    is_active/soft-delete state). Never used by any customer-facing endpoint."""
    base = map_shop_doc(doc)
    base.update({
        "city": doc.get("city", ""),
        "state": doc.get("state", ""),
        "ownerName": doc.get("owner_name", ""),
        "ownerEmail": doc.get("owner_email", ""),
        "website": doc.get("website", ""),
        "instagram": doc.get("instagram", ""),
        "reviews": doc.get("reviews", 0),
        "notes": doc.get("notes", ""),
    })
    return base


ADMIN_EDITABLE_SHOP_FIELDS = {
    "name", "area", "address", "city", "state", "phone", "lat", "lng",
    "rate_bw", "rate_color", "color", "spiral", "open24", "hours",
    "rating", "reviews", "owner_name", "owner_email",
    "website", "instagram", "notes",
}
_ADMIN_NUMERIC_FIELDS = {"rate_bw", "rate_color", "lat", "lng", "rating", "reviews"}
_ADMIN_BOOL_FIELDS = {"color", "spiral", "open24"}
MAX_SHOP_IMAGES = 3


def _clean_image_urls(value):
    """Coerces a client-supplied `image_urls` into a clean list of up to MAX_SHOP_IMAGES
    non-empty URL strings, or None if `value` isn't even a list. Silently caps rather than
    erroring on >3 — the admin panel's own upload UI already enforces the limit, so this is
    a defensive boundary check, not the primary UX control."""
    if not isinstance(value, list):
        return None
    cleaned = [str(u).strip() for u in value if isinstance(u, str) and str(u).strip()]
    return cleaned[:MAX_SHOP_IMAGES]


def _clean_admin_shop_fields(updates: dict):
    """Shared validation/coercion for admin create+update — returns (clean_dict, error)."""
    clean = {}
    if "image_urls" in updates:
        urls = _clean_image_urls(updates["image_urls"])
        if urls is None:
            return None, "'image_urls' must be a list of image URLs."
        clean["image_urls"] = urls
    for key in ADMIN_EDITABLE_SHOP_FIELDS:
        if key not in updates or updates[key] in (None, ""):
            continue
        if key in _ADMIN_NUMERIC_FIELDS:
            try:
                clean[key] = float(updates[key])
            except (TypeError, ValueError):
                return None, f"'{key}' must be a number."
        elif key in _ADMIN_BOOL_FIELDS:
            clean[key] = bool(updates[key])
        else:
            clean[key] = str(updates[key]).strip()
    if "lat" in clean and not (-90 <= clean["lat"] <= 90):
        return None, "Latitude must be between -90 and 90."
    if "lng" in clean and not (-180 <= clean["lng"] <= 180):
        return None, "Longitude must be between -180 and 180."
    for rate_key in ("rate_bw", "rate_color"):
        if rate_key in clean and clean[rate_key] < 0:
            return None, f"'{rate_key}' cannot be negative."
    return clean, None


def admin_list_all_shops_handler():
    """All shops including soft-deleted (is_active=False) ones — the super-admin panel's
    Active/Deleted tabs need both, unlike the public directory which only ever shows
    active shops."""
    docs = list(db_main.shops.find({}).sort("name", 1))
    return {"status": 200, "shops": [map_shop_doc_admin(d) for d in docs]}


def admin_create_shop_handler(data: dict):
    """Onboards a new print shop. Requires name/area/address/phone/lat/lng at minimum —
    everything else (rates, capabilities, photo, owner contact) is optional and can be
    filled in later via admin_update_shop_handler. Does NOT provision a shop_staff login
    itself — see auth_handler.register_shop_staff, called separately by the view so a
    shop can be onboarded even before its owner's login credentials are decided."""
    required = ("name", "area", "address", "phone", "lat", "lng")
    missing = [f for f in required if not data.get(f) and data.get(f) != 0]
    if missing:
        return {"status": 400, "error": f"Missing required field(s): {', '.join(missing)}."}

    clean, error = _clean_admin_shop_fields(data)
    if error:
        return {"status": 400, "error": error}
    for f in required:
        if f not in clean:
            return {"status": 400, "error": f"'{f}' is required."}

    if db_main.shops.find_one({"name": clean["name"]}):
        return {"status": 409, "error": "A shop with this name already exists."}

    clean["is_active"] = True
    result = db_main.shops.insert_one(clean)
    doc = db_main.shops.find_one({"_id": result.inserted_id})
    return {"status": 201, "shop": map_shop_doc_admin(doc)}


def admin_update_shop_handler(shop_id: str, updates: dict):
    """Platform-admin editing of ANY field on ANY shop — distinct from update_shop_handler
    (self-service, owner-only, restricted field set). Caller (views.py) has already
    verified the ADMIN_TOKEN."""
    if not ObjectId.is_valid(shop_id):
        return {"status": 404, "error": "Shop not found."}
    if not db_main.shops.find_one({"_id": ObjectId(shop_id)}):
        return {"status": 404, "error": "Shop not found."}

    clean, error = _clean_admin_shop_fields(updates)
    if error:
        return {"status": 400, "error": error}
    if not clean:
        return {"status": 400, "error": "No editable fields were provided."}

    db_main.shops.update_one({"_id": ObjectId(shop_id)}, {"$set": clean})
    doc = db_main.shops.find_one({"_id": ObjectId(shop_id)})
    return {"status": 200, "shop": map_shop_doc_admin(doc)}


def admin_delete_shop_handler(shop_id: str):
    """Soft-delete — sets is_active=False so the shop disappears from the public
    directory but its history (orders, staff logins) is preserved and it can be
    restored. Mirrors khelomore-server's cafe soft-delete/restore pattern exactly."""
    if not ObjectId.is_valid(shop_id):
        return {"status": 404, "error": "Shop not found."}
    result = db_main.shops.update_one({"_id": ObjectId(shop_id)}, {"$set": {"is_active": False}})
    if result.matched_count == 0:
        return {"status": 404, "error": "Shop not found."}
    return {"status": 200, "message": "Shop deactivated."}


def admin_restore_shop_handler(shop_id: str):
    if not ObjectId.is_valid(shop_id):
        return {"status": 404, "error": "Shop not found."}
    result = db_main.shops.update_one({"_id": ObjectId(shop_id)}, {"$set": {"is_active": True}})
    if result.matched_count == 0:
        return {"status": 404, "error": "Shop not found."}
    doc = db_main.shops.find_one({"_id": ObjectId(shop_id)})
    return {"status": 200, "shop": map_shop_doc_admin(doc)}


EDITABLE_SHOP_FIELDS = {"rate_bw", "rate_color", "hours", "color", "spiral", "open24", "phone", "address"}


def update_shop_handler(shop_id: str, updates: dict):
    """Shop-owner self-service profile editing (rates/hours/capability flags) — restricted
    to the fields in EDITABLE_SHOP_FIELDS so an arbitrary request body can never touch
    name/lat/lng/is_active/owner_email etc. Caller (views.py) has already verified the
    requesting staff member's own shop_id matches shop_id and that their role is 'owner'."""
    if not ObjectId.is_valid(shop_id):
        return {"status": 404, "error": "Shop not found."}
    if not db_main.shops.find_one({"_id": ObjectId(shop_id)}):
        return {"status": 404, "error": "Shop not found."}

    clean = {}
    if "image_urls" in updates:
        urls = _clean_image_urls(updates["image_urls"])
        if urls is None:
            return {"status": 400, "error": "'image_urls' must be a list of image URLs."}
        clean["image_urls"] = urls
    for key in EDITABLE_SHOP_FIELDS:
        if key not in updates:
            continue
        if key in ("rate_bw", "rate_color"):
            try:
                value = float(updates[key])
            except (TypeError, ValueError):
                return {"status": 400, "error": f"'{key}' must be a number."}
            if value < 0:
                return {"status": 400, "error": f"'{key}' cannot be negative."}
            clean[key] = value
        elif key in ("color", "spiral", "open24"):
            clean[key] = bool(updates[key])
        else:
            clean[key] = str(updates[key]).strip()

    if not clean:
        return {"status": 400, "error": "No editable fields were provided."}

    db_main.shops.update_one({"_id": ObjectId(shop_id)}, {"$set": clean})
    doc = db_main.shops.find_one({"_id": ObjectId(shop_id)})
    return {"status": 200, "shop": map_shop_doc(doc)}


def parse_google_maps_url_handler(url):
    """Parses a Google Maps link (short or long redirect) to extract coordinates and place
    name. Ported verbatim from khelomore-server/.../Handlers/cafes.py's
    parse_google_maps_url_handler for the super-admin 'Add Shop' form's Maps-link import."""
    import re
    import requests
    from urllib.parse import unquote, urlsplit

    if not url:
        return {"status": "error", "message": "URL parameter is required."}

    # SECURITY: public/unauthenticated endpoint (same reasoning as khelomore-server) — a
    # substring check like `"goo.gl" in url` is an SSRF hole; only actually follow the
    # redirect when the URL's real hostname is Google's own shortener domain.
    try:
        hostname = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return {"status": "error", "message": "Invalid URL."}

    resolved_url = url
    if hostname in ("goo.gl", "maps.app.goo.gl"):
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            res = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
            resolved_url = res.url
        except Exception as e:
            return {"status": "error", "message": f"Failed to resolve short link: {e}"}

    lat = None
    lon = None

    match = re.search(r'!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)', resolved_url)
    if match:
        lat = float(match.group(1))
        lon = float(match.group(2))
    else:
        match = re.search(r'@(-?\d+\.\d+),(-?\d+\.\d+)', resolved_url)
        if match:
            lat = float(match.group(1))
            lon = float(match.group(2))
        else:
            match = re.search(r'[?&](q|query|ll)=(-?\d+\.\d+),(-?\d+\.\d+)', resolved_url)
            if match:
                lat = float(match.group(2))
                lon = float(match.group(3))

    address = ""
    match_addr = re.search(r'/place/([^/?]+)', resolved_url)
    if match_addr:
        address = unquote(match_addr.group(1)).replace("+", " ")
        if "@" in address:
            address = address.split("/@")[0]
    else:
        match_addr = re.search(r'/maps/dir/[^/]+/([^/?]+)', resolved_url)
        if match_addr:
            address = unquote(match_addr.group(1)).replace("+", " ")

    if lat is None or lon is None:
        return {"status": "error", "message": "Could not extract coordinates from Google Maps link."}

    return {"status": "success", "latitude": lat, "longitude": lon, "address": address}


def seed_shops_handler():
    """One-time idempotent seed — inserts SEED_SHOPS only for names not already present,
    so re-running this after an admin has since edited a shop never clobbers real data."""
    inserted = []
    for shop in SEED_SHOPS:
        if db_main.shops.find_one({"name": shop["name"]}):
            continue
        doc = dict(shop)
        doc["is_active"] = True
        result = db_main.shops.insert_one(doc)
        inserted.append(str(result.inserted_id))
    return {"status": 200, "inserted": inserted, "skipped": len(SEED_SHOPS) - len(inserted)}
