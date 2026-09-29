"""Account-deletion API and lifecycle tests using an isolated Mongo mock."""

import asyncio
from datetime import datetime, timedelta
import os
import unittest
from unittest.mock import AsyncMock, Mock, patch

from bson import ObjectId
import gridfs
import httpx
import mongomock

with patch.dict(os.environ, {
    "MONGO_URL": "mongodb://localhost:27017",
    "DB_NAME": "dishfinder_test",
    "JWT_SECRET": "test-secret-" * 4,
}), patch("dotenv.load_dotenv", return_value=False):
    import server


class AsyncCursor:
    def __init__(self, cursor):
        self.cursor = iter(cursor)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self.cursor)
        except StopIteration:
            raise StopAsyncIteration


class AsyncCollection:
    """Expose the Motor operations under test over mongomock's query engine."""

    def __init__(self, collection):
        self.collection = collection

    def find(self, *args, **kwargs):
        return AsyncCursor(self.collection.find(*args, **kwargs))

    def __getattr__(self, name):
        async def call(*args, **kwargs):
            return getattr(self.collection, name)(*args, **kwargs)
        return call


class AccountDeletionTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "correct-password"
        cls.password_hash = server.pwd_context.using(bcrypt__rounds=4).hash(cls.password)

    async def asyncSetUp(self):
        self.database = mongomock.MongoClient().db
        for name in ("users", "sessions", "favourites", "search_history", "subscriptions", "devices", "device_quotas"):
            replacement = AsyncCollection(self.database[name])
            patcher = patch.object(server, f"{name}_collection", replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.now = datetime(2026, 9, 29, 12, 0, 0)
        clock = patch.object(server, "utcnow", return_value=self.now)
        clock.start()
        self.addCleanup(clock.stop)
        self.image_id = ObjectId()
        self.file_store = Mock(delete=AsyncMock())
        file_patch = patch.object(server, "fs", self.file_store)
        file_patch.start()
        self.addCleanup(file_patch.stop)
        self.device_token = "test-device-token-" * 3
        self.device = {
            "_id": server.token_hash(self.device_token),
            "quota_id": "quota-1", "guest_user_id": "guest-1",
        }
        self.database.devices.insert_one(self.device)
        self.database.device_quotas.insert_one({"_id": "quota-1", "search_count": 3})
        self.user = {
            "id": "user-1", "email": "person@example.com",
            "password_hash": self.password_hash, "is_anonymous": False,
            "is_email_verified": True, "legacy_quota_migrated": True,
            "profileImageId": str(self.image_id),
        }
        self.database.users.insert_many([
            self.user, {**self.user, "id": "user-2", "email": "other@example.com", "profileImageId": str(ObjectId())},
            {"id": "guest-1", "is_anonymous": True, "legacy_quota_migrated": True},
        ])
        for name in ("favourites", "search_history", "subscriptions"):
            self.database[name].insert_many([{"user_id": "user-1"}, {"user_id": "user-2"}, {"user_id": "guest-1"}])
        self.http = httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://test")
        self.addAsyncCleanup(self.http.aclose)
        self.tokens = await server.issue_session(self.user, self.device)
        self.second_tokens = await server.issue_session(self.user, self.device)
        await server.issue_session({**self.user, "id": "user-2"}, self.device)
        self.headers = {"Authorization": f"Bearer {self.tokens['access_token']}"}

    async def request_deletion(self, days, **overrides):
        return await self.http.post("/api/auth/delete-account", headers=self.headers,
                                    json={"password": self.password, "grace_period_days": days, **overrides})

    async def login(self, password=None):
        return await self.http.post("/api/auth/login", headers={"X-Device-Token": self.device_token},
                                    json={"email": self.user["email"], "password": password or self.password})

    def assert_personal_data_removed(self):
        self.assertIsNone(self.database.users.find_one({"id": "user-1"}))
        for name in ("sessions", "favourites", "search_history", "subscriptions"):
            self.assertEqual(self.database[name].count_documents({"user_id": "user-1"}), 0)
            self.assertGreater(self.database[name].count_documents({"user_id": "user-2"}), 0)
        self.assertIsNotNone(self.database.users.find_one({"id": "guest-1"}))
        self.assertEqual(self.database.device_quotas.find_one({"_id": "quota-1"})["search_count"], 3)
        self.assertIsNotNone(self.database.devices.find_one({"_id": self.device["_id"]}))
        self.file_store.delete.assert_awaited_with(self.image_id)

    async def test_immediate_deletion_cascades_and_preserves_other_accounts_and_quota(self):
        response = await self.request_deletion(0)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {
            "success": True, "message": "Account deleted successfully.", "status": "deleted",
            "grace_period_days": 0, "deletion_requested_at": "2026-09-29T12:00:00Z",
            "delete_after": "2026-09-29T12:00:00Z", "can_cancel": False,
        })
        self.assert_personal_data_removed()
        self.assertEqual((await self.http.get("/api/auth/me", headers=self.headers)).status_code, 401)

    async def test_both_grace_periods_keep_data_and_revoke_every_session(self):
        for days in (15, 30):
            with self.subTest(days=days):
                response = await self.request_deletion(days)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["status"], "scheduled")
                self.assertTrue(response.json()["can_cancel"])
                account = self.database.users.find_one({"id": "user-1"})
                self.assertEqual(account["delete_after"], self.now + timedelta(days=days))
                self.assertEqual(self.database.favourites.count_documents({"user_id": "user-1"}), 1)
                self.assertEqual(self.database.sessions.count_documents({"user_id": "user-1", "revoked_at": None}), 0)
                for tokens in (self.tokens, self.second_tokens):
                    result = await self.http.get("/api/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
                    self.assertEqual(result.status_code, 401)
                refresh = await self.http.post("/api/auth/refresh", headers={"X-Device-Token": self.device_token},
                                               json={"refresh_token": self.tokens["refresh_token"]})
                self.assertEqual(refresh.status_code, 401)
                await server.process_due_account_deletions()
                self.assertIsNotNone(self.database.users.find_one({"id": "user-1"}))
                result = await self.login()
                self.assertEqual(result.status_code, 200, result.text)
                self.assertTrue(result.json()["account_deletion_cancelled"])
                self.headers = {"Authorization": f"Bearer {result.json()['access_token']}"}

    async def test_invalid_payload_password_and_missing_auth_do_not_delete(self):
        for days in (1, 14, 31, -1, "15", False, 15.0):
            self.assertEqual((await self.request_deletion(days)).status_code, 422)
        self.assertEqual((await self.request_deletion(0, user_id="user-2")).status_code, 422)
        self.assertEqual((await self.request_deletion(0, password="wrong-password")).status_code, 401)
        response = await self.http.post("/api/auth/delete-account", json={"password": self.password, "grace_period_days": 0})
        self.assertEqual(response.status_code, 401)
        self.assertIsNotNone(self.database.users.find_one({"id": "user-1"}))
        self.file_store.delete.assert_not_awaited()

    async def test_guest_cannot_delete_and_unverified_account_can_delete(self):
        guest = self.database.users.find_one({"id": "guest-1"})
        tokens = await server.issue_session(guest, self.device)
        response = await self.http.post("/api/auth/delete-account", headers={"Authorization": f"Bearer {tokens['access_token']}"},
                                        json={"password": self.password, "grace_period_days": 0})
        self.assertEqual(response.status_code, 403)
        self.database.users.update_one({"id": "user-1"}, {"$set": {"is_email_verified": False}})
        self.assertEqual((await self.request_deletion(0)).status_code, 200)

    async def test_wrong_login_does_not_restore_and_valid_login_preserves_data(self):
        await self.request_deletion(15)
        self.assertEqual((await self.login("wrong-password")).status_code, 401)
        self.assertEqual(self.database.users.find_one({"id": "user-1"})["deletion_status"], "pending")
        result = await self.login()
        self.assertEqual(result.status_code, 200, result.text)
        self.assertTrue(result.json()["account_deletion_cancelled"])
        self.assertNotIn("delete_after", self.database.users.find_one({"id": "user-1"}))
        with patch.object(server, "utcnow", return_value=self.now + timedelta(days=31)):
            await server.process_due_account_deletions()
        self.assertIsNotNone(self.database.users.find_one({"id": "user-1"}))

    async def test_login_at_deadline_fails_even_before_worker_runs(self):
        await self.request_deletion(15)
        with patch.object(server, "utcnow", return_value=self.now + timedelta(days=15)):
            response = await self.login()
            self.assertEqual(response.status_code, 401)
            await server.process_due_account_deletions()
        self.assert_personal_data_removed()

    async def test_worker_rechecks_a_candidate_after_login_cancellation(self):
        await self.request_deletion(15)
        candidate = self.database.users.find_one({"id": "user-1"})
        await self.login()
        # Simulate a worker snapshot taken before the login cancelled deletion.
        with patch.object(server.users_collection, "find", return_value=AsyncCursor([candidate])):
            await server.process_due_account_deletions()
        self.assertIsNotNone(self.database.users.find_one({"id": "user-1"}))
        self.file_store.delete.assert_not_awaited()

    async def test_failed_cleanup_retries_and_cannot_be_restored(self):
        await self.request_deletion(15)
        self.file_store.delete.side_effect = RuntimeError("temporary storage error")
        with patch.object(server, "utcnow", return_value=self.now + timedelta(days=16)), self.assertLogs(server.logger, level="ERROR"):
            await server.process_due_account_deletions()
        self.assertEqual(self.database.users.find_one({"id": "user-1"})["deletion_status"], "deleting")
        self.assertEqual((await self.login()).status_code, 401)
        self.file_store.delete.side_effect = gridfs.errors.NoFile("already removed")
        await server.process_due_account_deletions()
        self.assert_personal_data_removed()

    async def test_pending_state_blocks_tokens_even_if_session_revocation_failed(self):
        self.database.users.update_one({"id": "user-1"}, {"$set": {
            "deletion_status": "pending", "delete_after": self.now + timedelta(days=15),
        }})
        self.assertEqual((await self.http.get("/api/auth/me", headers=self.headers)).status_code, 401)
        result = await self.http.post("/api/auth/refresh", headers={"X-Device-Token": self.device_token},
                                      json={"refresh_token": self.tokens["refresh_token"]})
        self.assertEqual(result.status_code, 401)
        self.assertEqual(self.database.users.find_one({"id": "user-1"})["deletion_status"], "pending")

    async def test_immediate_cleanup_failure_is_reported_and_worker_retries(self):
        self.file_store.delete.side_effect = RuntimeError("temporary storage error")
        with self.assertLogs(server.logger, level="ERROR"):
            response = await self.request_deletion(0)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"]["code"], "ACCOUNT_DELETION_REQUEST_SAVED")
        self.assertEqual(self.database.users.find_one({"id": "user-1"})["deletion_status"], "deleting")
        self.assertEqual((await self.login()).status_code, 401)
        self.file_store.delete.side_effect = None
        await server.process_due_account_deletions()
        self.assert_personal_data_removed()

    async def test_startup_runs_cleanup_and_shutdown_stops_worker(self):
        scanned = asyncio.Event()

        async def scan():
            scanned.set()

        # mongomock does not fully implement Mongo's partial unique indexes.
        with patch.object(server, "process_due_account_deletions", side_effect=scan), \
                patch.object(server, "client") as client, \
                patch.object(server.users_collection, "create_index", new=AsyncMock()) as create_index:
            await server.initialise_database()
            create_index.assert_any_await([("deletion_status", 1), ("delete_after", 1)])
            await asyncio.wait_for(scanned.wait(), timeout=1)
            task = server.app.state.account_deletion_task
            self.assertFalse(task.done())
            await server.shutdown_db_client()
            self.assertTrue(task.cancelled())
            client.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
