# payments.py
# Cashfree integration for QuickPrint. Ported directly from
# khelomore-server/.../Handlers/payments.py's platform-account code path — QuickPrint has
# no per-shop "connect your own gateway" concept (unlike BookMyConsole's per-cafe
# routing), every order is paid straight into QuickPrint's own Cashfree account, so this
# is the simpler subset of that file: no cafe_id-keyed credential lookup, no slot holds.

import uuid
import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

CASHFREE_API_VERSION = "2023-08-01"


def _cashfree_base_url():
    """Sandbox vs production Cashfree API host, switched by a single env var
    (CASHFREE_ENV) — flipping to production later is a one-line settings change, not a
    redeploy of different logic. Identical to khelomore-server."""
    env = getattr(settings, "CASHFREE_ENV", "sandbox")
    return "https://sandbox.cashfree.com/pg" if env != "production" else "https://api.cashfree.com/pg"


def _cashfree_headers(client_id, client_secret):
    return {
        "x-client-id": client_id,
        "x-client-secret": client_secret,
        "x-api-version": CASHFREE_API_VERSION,
        "Content-Type": "application/json",
    }


_used_payments_index_ensured = False


def _ensure_used_payments_index():
    global _used_payments_index_ensured
    if not _used_payments_index_ensured:
        try:
            from .db_connection import db_main
            db_main.used_cashfree_payments.create_index("order_id", unique=True)
        except Exception:
            pass
        _used_payments_index_ensured = True


def create_cashfree_order_handler(amount_in_inr, customer_email=None, customer_phone=None):
    """
    Creates a real Cashfree Order for a print job payment. Amount is in standard INR
    (not paise) — Cashfree's own API takes rupees directly.

    Falls back to a mock order (is_mock: True) if platform credentials aren't
    configured yet or the Cashfree API call fails — same graceful-degradation contract
    as khelomore-server, so local development never hard-blocks on missing sandbox keys.
    """
    client_id = getattr(settings, "CASHFREE_CLIENT_ID", "")
    client_secret = getattr(settings, "CASHFREE_CLIENT_SECRET", "")

    order_amount = round(float(amount_in_inr), 2)
    order_id = f"order_{uuid.uuid4().hex[:20]}"
    customer_id = uuid.uuid5(uuid.NAMESPACE_DNS, customer_email or order_id).hex[:24]

    if not client_id or not client_secret:
        logger.warning("[Cashfree] Missing CASHFREE_CLIENT_ID or CASHFREE_CLIENT_SECRET. Generating mock order.")
        return {
            "order_id": order_id,
            "order_amount": order_amount,
            "order_currency": "INR",
            "order_status": "ACTIVE",
            "payment_session_id": f"session_mock_{uuid.uuid4().hex[:16]}",
            "is_mock": True,
        }

    try:
        payload = {
            "order_id": order_id,
            "order_amount": order_amount,
            "order_currency": "INR",
            "customer_details": {
                "customer_id": customer_id,
                "customer_email": customer_email or "guest@quickprint.app",
                "customer_phone": customer_phone or "9999999999",
            },
            # The web checkout's Cashfree JS SDK never actually navigates here — same
            # interception pattern as khelomore-server's mobile WebView, adapted for web:
            # the SDK's own checkout() callback fires on completion before any redirect
            # happens. {order_id} is Cashfree's own template placeholder.
            "order_meta": {
                "return_url": f"{getattr(settings, 'CUSTOMER_WEB_URL', '')}/orders/{{order_id}}?payment=return",
            },
        }
        response = requests.post(
            f"{_cashfree_base_url()}/orders",
            headers=_cashfree_headers(client_id, client_secret),
            json=payload,
            timeout=15,
        )
        response.raise_for_status()
        order = response.json()
        logger.info(f"[Cashfree] Successfully created order: {order.get('order_id')}")
        return order
    except Exception as e:
        logger.error(f"[Cashfree] Exception during order creation: {str(e)}. Falling back to mock.", exc_info=True)
        return {
            "order_id": order_id,
            "order_amount": order_amount,
            "order_currency": "INR",
            "order_status": "ACTIVE",
            "payment_session_id": f"session_mock_{uuid.uuid4().hex[:16]}",
            "error_msg": str(e),
            "is_mock": True,
        }


def verify_cashfree_payment(order_id, expected_amount_paise):
    """
    Verifies a completed Cashfree payment server-side. No client-side signature to check
    — the client only ever received a payment_session_id, never a secret — so this
    independently asks Cashfree's own API (using OUR credentials) what actually happened.
    Returns True only if ALL of:
      1. Cashfree's own records show this exact order_id has order_status == "PAID".
      2. The order was paid at EXACTLY expected_amount_paise (converted to rupees) — a
         client could otherwise pay ₹1 for a genuinely different order and reuse that
         success to unlock a ₹500 print job.
      3. This order_id has not already been used for an earlier order (replay
         protection) — one paid order may only ever unlock one print job.
    On success, atomically claims the order_id so it can never be reused. Identical
    security model to khelomore-server's verify_cashfree_payment, minus the per-cafe
    credential-routing piece QuickPrint doesn't need.
    """
    # SECURITY: order_id arrives straight from the client's JSON body — fail closed on
    # anything that isn't a plain non-empty string (a dict here could otherwise corrupt
    # the used_cashfree_payments filter below into matching anything).
    if not isinstance(order_id, str) or not order_id:
        return False

    client_id = getattr(settings, "CASHFREE_CLIENT_ID", "")
    client_secret = getattr(settings, "CASHFREE_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        logger.warning("[Cashfree] Missing credentials — cannot verify payment.")
        return False

    try:
        response = requests.get(
            f"{_cashfree_base_url()}/orders/{order_id}",
            headers=_cashfree_headers(client_id, client_secret),
            timeout=15,
        )
        response.raise_for_status()
        order = response.json()
    except Exception as e:
        logger.error(f"[Cashfree] Failed to fetch order {order_id}: {str(e)}", exc_info=True)
        return False

    expected_amount_inr = expected_amount_paise / 100
    order_amount = order.get("order_amount")
    if order_amount is None or round(float(order_amount), 2) != round(expected_amount_inr, 2):
        logger.warning(
            f"[Cashfree] Amount mismatch on order {order_id}: order={order_amount} expected={expected_amount_inr}"
        )
        return False

    if order.get("order_status") != "PAID":
        logger.warning(f"[Cashfree] Order {order_id} is not fully paid (status={order.get('order_status')}).")
        return False

    _ensure_used_payments_index()
    from .db_connection import db_main
    try:
        claim = db_main.used_cashfree_payments.update_one(
            {"order_id": order_id},
            {"$setOnInsert": {"order_id": order_id}},
            upsert=True,
        )
    except Exception as e:
        # Duplicate key on the unique index also means "already used" — treat as replay.
        logger.warning(f"[Cashfree] Payment claim failed for order {order_id}: {str(e)}")
        return False

    if claim.upserted_id is None:
        logger.warning(f"[Cashfree] Order {order_id} has already been used — replay blocked.")
        return False

    return True
