"""One-time migration from legacy device identifiers to server-issued user IDs.

Run `python migrate_device_id_to_account.py --dry-run` first.  It only rewrites
records whose `user_id` is literally a known legacy device ID, then removes the
obsolete `device_id` field. User IDs and their existing favourites/history are
otherwise retained, so account registration can upgrade an anonymous document
without losing data.
"""
import argparse
import asyncio
import os
from pathlib import Path

# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]
from motor.motor_asyncio import AsyncIOMotorClient


async def run_migration(dry_run: bool) -> None:
    load_dotenv(Path(__file__).parent / ".env")
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    users = db.users
    collections = (db.favourites, db.search_history)

    device_to_user = {
        user["device_id"]: user["id"]
        async for user in users.find({"device_id": {"$type": "string"}, "id": {"$type": "string"}})
        if user.get("device_id")
    }
    print(f"Found {len(device_to_user)} legacy device identities.")

    for collection in collections:
        changed = deleted_duplicates = 0
        async for document in collection.find({"user_id": {"$in": list(device_to_user)}}):
            target_user_id = device_to_user[document["user_id"]]
            if collection.name == "favourites":
                duplicate = await collection.find_one({"user_id": target_user_id, "place_id": document.get("place_id")})
                if duplicate and duplicate["_id"] != document["_id"]:
                    deleted_duplicates += 1
                    if not dry_run:
                        await collection.delete_one({"_id": document["_id"]})
                    continue
            changed += 1
            if not dry_run:
                await collection.update_one({"_id": document["_id"]}, {"$set": {"user_id": target_user_id}})
        print(f"{collection.name}: {changed} IDs rewritten, {deleted_duplicates} duplicate favourites removed.")

    if dry_run:
        print(f"Would remove device_id from {len(device_to_user)} users.")
    else:
        result = await users.update_many({"device_id": {"$exists": True}}, {"$unset": {"device_id": ""}})
        print(f"Removed device_id from {result.modified_count} users.")
    client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate legacy DishFinder device identities")
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing data")
    args = parser.parse_args()
    asyncio.run(run_migration(args.dry_run))
