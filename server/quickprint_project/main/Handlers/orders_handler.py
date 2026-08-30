# orders_handler.py
# Print-job order lifecycle. Two-step create → pay → confirm flow, same shape as every
# payment-gated creation flow built this session (BookMyConsole bookings, Olde Bailey's
# orders): a Cashfree order is created for a server-computed amount, the customer pays,
# and a separate confirm step independently re-verifies that payment before the order is
# actually placed — nothing is ever created as "paid" off a client's say-so.

import random
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from .db_connection import db_main
from . import pricing
from . import payments
from .uploads import delete_print_document

IST = timezone(timedelta(hours=5, minutes=30))

VALID_COLORS = {"bw", "color"}
VALID_RANGE_MODES = {"all", "custom"}
MAX_COPIES = 50

# queued -> printing -> ready -> collected is the normal path; cancelled is only
# reachable from the two states before real work has committed (queued/printing) — once
# a job is "ready" the shop has already spent the paper/ink, so cancellation is no
# longer a status transition, only a support/refund conversation outside this flow.
STATUS_TRANSITIONS = {
    "queued": {"printing", "cancelled"},
    "printing": {"ready", "cancelled"},
    "ready": {"collected"},
}


def _generate_unique_pin(shop_id: str) -> str:
    """4-digit PIN, unique among this shop's currently-active orders (queued/printing/
    ready) — a collected/cancelled order's old PIN can be reused, it's no longer live."""
    active = set(
        db_main.orders.find(
            {"shop_id": shop_id, "status": {"$in": ["queued", "printing", "ready"]}},
            {"pin": 1},
        )
    )
    active_pins = {d.get("pin") for d in active}
    for _ in range(50):
        candidate = f"{random.randint(0, 9999):04d}"
        if candidate not in active_pins:
            return candidate
    # Astronomically unlikely (50 collisions against at most a few thousand possible
    # 4-digit codes and a realistically tiny active-order count) — fail loud rather than
    # ever hand out a duplicate PIN.
    raise RuntimeError("Could not allocate a unique pickup PIN.")


def _next_slot_number(shop_id: str, date_str: str) -> str:
    """Sequential per shop per day — 'Slot 1', 'Slot 2', ... resets naturally each day
    since it's derived from that day's order count, not a stored counter."""
    count = db_main.orders.count_documents({"shop_id": shop_id, "order_date": date_str})
    return f"Slot {count + 1}"


def _validate_order_config(cfg: dict, page_count: int) -> str | None:
    if cfg.get("color") not in VALID_COLORS:
        return "Invalid colour option."
    if cfg.get("paper") not in pricing.PAPERS:
        return "Invalid paper option."
    range_mode = cfg.get("range_mode")
    if range_mode not in VALID_RANGE_MODES:
        return "Invalid print range option."
    try:
        copies = int(cfg.get("copies", 1))
    except (TypeError, ValueError):
        return "Invalid copy count."
    if copies < 1 or copies > MAX_COPIES:
        return f"Copies must be between 1 and {MAX_COPIES}."
    for addon_id in cfg.get("addons") or []:
        if addon_id not in pricing.ADDONS:
            return f"Unknown add-on '{addon_id}'."

    if range_mode == "all":
        selected = page_count
    else:
        selected = len(pricing.parse_range(cfg.get("custom_range", ""), page_count))
    if selected == 0:
        return "Your page range selects zero pages."
    return None


def create_order_draft(user_email: str, shop_id: str, upload_id: str, cfg: dict):
    """
    Step 1: validates the job config against the shop and the SERVER-VERIFIED upload
    record (never a client-claimed page count — see uploads.py/pending_uploads), prices
    it server-side, and opens a Cashfree order for that exact amount.
    """
    if not ObjectId.is_valid(shop_id):
        return {"status": 400, "error": "Invalid shop."}
    shop = db_main.shops.find_one({"_id": ObjectId(shop_id), "is_active": {"$ne": False}})
    if not shop:
        return {"status": 404, "error": "Shop not found or no longer active."}

    if not ObjectId.is_valid(upload_id):
        return {"status": 400, "error": "Invalid upload."}
    upload = db_main.pending_uploads.find_one({"_id": ObjectId(upload_id), "user_email": user_email})
    if not upload:
        return {"status": 404, "error": "Upload not found or expired — please re-upload your document."}

    page_count = upload["page_count"]
    error = _validate_order_config(cfg, page_count)
    if error:
        return {"status": 400, "error": error}

    price_cfg = {**cfg, "page_count": page_count}
    bill = pricing.price_order(price_cfg, shop)

    order = payments.create_cashfree_order_handler(bill["total"], customer_email=user_email)

    order_doc = {
        "user_email": user_email,
        "shop_id": shop_id,
        "file_url": upload["file_url"],
        "file_name": upload["file_name"],
        "page_count": page_count,
        "color": cfg.get("color"),
        "duplex": bool(cfg.get("duplex")),
        "paper": cfg.get("paper"),
        "range_mode": cfg.get("range_mode"),
        "custom_range": cfg.get("custom_range", ""),
        "copies": int(cfg.get("copies", 1)),
        "addons": cfg.get("addons") or [],
        "bill": bill,
        "total": bill["total"],
        "status": "pending_payment",
        "cashfree_order_id": order.get("order_id"),
        "pin": None,
        "slot": None,
        "order_date": datetime.now(IST).strftime("%Y-%m-%d"),
        "created_at": datetime.now(IST).isoformat(),
    }
    result = db_main.orders.insert_one(order_doc)

    return {
        "status": 200,
        "order_id": str(result.inserted_id),
        "cashfree_order_id": order.get("order_id"),
        "payment_session_id": order.get("payment_session_id"),
        "total": bill["total"],
        "is_mock": order.get("is_mock", False),
    }


def confirm_order_payment(order_id: str, user_email: str, cashfree_order_id: str):
    """
    Step 2: independently re-verifies the Cashfree payment against the order's own
    server-computed total (set at draft time, never re-read from the client here) before
    finalizing anything. Only on real, verified success does a PIN/slot get issued —
    keeps pickup PINs scarce and meaningful instead of handed out to abandoned carts.
    """
    if not ObjectId.is_valid(order_id):
        return {"status": 400, "error": "Invalid order."}
    order = db_main.orders.find_one({"_id": ObjectId(order_id), "user_email": user_email})
    if not order:
        return {"status": 404, "error": "Order not found."}
    if order["status"] != "pending_payment":
        return {"status": 409, "error": f"This order is already {order['status']}."}
    if order.get("cashfree_order_id") != cashfree_order_id:
        return {"status": 400, "error": "Payment order mismatch."}

    expected_paise = int(round(order["total"] * 100))
    if not payments.verify_cashfree_payment(cashfree_order_id, expected_paise):
        return {"status": 402, "error": "Payment verification failed. Please complete payment before continuing."}

    pin = _generate_unique_pin(order["shop_id"])
    slot = _next_slot_number(order["shop_id"], order["order_date"])
    db_main.orders.update_one(
        {"_id": order["_id"]},
        {"$set": {"status": "queued", "pin": pin, "slot": slot, "paid_at": datetime.now(IST).isoformat()}},
    )
    db_main.pending_uploads.delete_many({"user_email": user_email, "file_url": order["file_url"]})

    return _serialize_order({**order, "status": "queued", "pin": pin, "slot": slot})


def _serialize_order(doc: dict) -> dict:
    return {
        "status": 200,
        "order": {
            "id": str(doc["_id"]) if "_id" in doc else doc.get("id"),
            "shopId": doc["shop_id"],
            "fileName": doc["file_name"],
            "pageCount": doc["page_count"],
            "color": doc["color"],
            "duplex": doc["duplex"],
            "paper": doc["paper"],
            "copies": doc["copies"],
            "addons": doc["addons"],
            "bill": doc["bill"],
            "total": doc["total"],
            "status": doc["status"],
            "pin": doc.get("pin"),
            "slot": doc.get("slot"),
            "createdAt": doc["created_at"],
        },
    }


def get_order_handler(order_id: str, user_email: str):
    if not ObjectId.is_valid(order_id):
        return {"status": 404, "error": "Order not found."}
    order = db_main.orders.find_one({"_id": ObjectId(order_id), "user_email": user_email})
    if not order:
        return {"status": 404, "error": "Order not found."}
    return _serialize_order(order)


def list_my_orders_handler(user_email: str):
    docs = list(db_main.orders.find({"user_email": user_email}).sort("created_at", -1))
    return {"status": 200, "orders": [_serialize_order(d)["order"] for d in docs]}


def list_shop_queue_handler(shop_id: str):
    """FIFO — oldest queued job first, matching the physical reality of a print counter."""
    docs = list(
        db_main.orders.find({"shop_id": shop_id, "status": {"$in": ["queued", "printing", "ready"]}}).sort(
            "created_at", 1
        )
    )
    orders = []
    for d in docs:
        entry = _serialize_order(d)["order"]
        entry["fileUrl"] = d["file_url"]  # shop dashboard needs this to actually download/print
        orders.append(entry)
    return {"status": 200, "orders": orders}


def list_shop_order_history_handler(shop_id: str):
    """All-time order history for a shop's revenue/analytics and order-history pages —
    unlike list_shop_queue_handler (live queue only), this includes collected/cancelled
    orders too, but still excludes pending_payment: those were never actually paid, so
    they're not real revenue history, just abandoned checkouts. Capped at 1000 — a
    reasonable window without unbounded response growth as a shop accumulates orders.

    Includes the customer's name/email — unlike the customer-facing serialization, the
    shop legitimately needs to know who placed each job (to call them, resolve a pickup
    dispute, etc.). Names are batch-fetched in one query rather than per-order to avoid
    an N+1 lookup against db_main.users."""
    docs = list(
        db_main.orders.find({"shop_id": shop_id, "status": {"$ne": "pending_payment"}})
        .sort("created_at", -1)
        .limit(1000)
    )
    emails = {d["user_email"] for d in docs if d.get("user_email")}
    users_by_email = {u["email"]: u for u in db_main.users.find({"email": {"$in": list(emails)}})}

    orders = []
    for d in docs:
        entry = _serialize_order(d)["order"]
        entry["paidAt"] = d.get("paid_at")
        user_email = d.get("user_email")
        entry["customerEmail"] = user_email
        entry["customerName"] = users_by_email.get(user_email, {}).get("name") if user_email else None
        orders.append(entry)
    return {"status": 200, "orders": orders}


def update_order_status_handler(order_id: str, shop_id: str, new_status: str):
    """shop_id is the AUTHENTICATED shop staff member's own shop — never trusted from an
    arbitrary request param, so a shop can only ever move its own queue's orders."""
    if not ObjectId.is_valid(order_id):
        return {"status": 404, "error": "Order not found."}
    order = db_main.orders.find_one({"_id": ObjectId(order_id), "shop_id": shop_id})
    if not order:
        return {"status": 404, "error": "Order not found."}

    allowed_next = STATUS_TRANSITIONS.get(order["status"], set())
    if new_status not in allowed_next:
        return {
            "status": 400,
            "error": f"Cannot move an order from '{order['status']}' to '{new_status}'.",
        }

    update = {"status": new_status}
    if new_status == "collected":
        update["collected_at"] = datetime.now(IST).isoformat()

    db_main.orders.update_one({"_id": order["_id"]}, {"$set": update})

    if new_status == "collected":
        # File privacy — makes quickprint-hub's "auto-wiped after pickup" UI copy
        # actually true. Best-effort; never blocks the status update itself.
        delete_print_document(order["file_url"])

    return _serialize_order({**order, "status": new_status})
