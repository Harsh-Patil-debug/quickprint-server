"""
One-time migration: the `shops` collection's old singular `image_url` field is being
replaced by `image_urls` (a list of up to 3 photos, so the mobile/web cards can show a
slider). This wraps any existing `image_url` into a 1-element `image_urls` list and removes
the old field, so shops seeded before this change don't just silently show zero photos.

Run once from quickprint-server/server:
    python migrate_shop_images.py
Safe to re-run — a shop with no `image_url` set (or already migrated) is left untouched.
"""
import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "server.settings")
django.setup()

from quickprint_project.main.Handlers.db_connection import db_main

migrated = 0
for doc in db_main.shops.find({"image_url": {"$exists": True}}):
    url = doc.get("image_url")
    update = {"$unset": {"image_url": ""}}
    if url:
        update["$set"] = {"image_urls": [url]}
    db_main.shops.update_one({"_id": doc["_id"]}, update)
    migrated += 1
    print(f"  migrated: {doc.get('name', doc['_id'])} -> image_urls={[url] if url else []}")

print(f"\nDone. {migrated} shop(s) migrated.")
