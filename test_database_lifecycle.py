"""Exercise Motor on the server's actual startup loop without contacting MongoDB."""

import asyncio
from contextlib import ExitStack
import os
import unittest
from unittest.mock import AsyncMock, patch

with patch.dict(os.environ, {
    "MONGO_URL": "mongodb://127.0.0.1:27017",
    "DB_NAME": "dishfinder_test",
    "JWT_SECRET": "test-secret-" * 4,
}), patch("dotenv.load_dotenv", return_value=False):
    # Import before asyncio.run(), as Vercel does before starting its lifespan.
    import server


class DatabaseLifecycleTests(unittest.TestCase):
    def test_database_and_gridfs_work_when_startup_uses_a_new_loop(self):
        def run_without_database(loop, method, *args, **kwargs):
            results = {"create_index": "test_index", "command": {"ok": 1}, "delete": None}
            self.assertIn(method.__name__, results)
            # Keep Motor's Future/loop behavior; replace only the blocking I/O.
            return loop.run_in_executor(None, lambda: results[method.__name__])

        async def run_lifespan():
            async with server.app.router.lifespan_context(server.app):
                self.assertIs(server.client.io_loop, asyncio.get_running_loop())
                self.assertIs(server.fs.get_io_loop(), asyncio.get_running_loop())
                response = await server.root()
                self.assertEqual(response["database"], "connected")
                self.assertEqual(response["database_name"], server.db.name)
                # File operations must use the same loop as the collections.
                await server.fs.delete("test-file")

        names = (
            "client", "db", "fs", "users_collection", "favourites_collection",
            "search_history_collection", "subscriptions_collection",
            "sessions_collection", "devices_collection", "device_quotas_collection",
        )
        with ExitStack() as patches:
            for name in names:
                patches.enter_context(patch.object(server, name, getattr(server, name)))
            patches.enter_context(patch("motor.frameworks.asyncio.run_on_executor", side_effect=run_without_database))
            patches.enter_context(patch.object(server, "process_due_account_deletions", new=AsyncMock()))
            # A later lifespan must also work after the previous client was closed.
            for _ in range(2):
                asyncio.run(run_lifespan())


if __name__ == "__main__":
    unittest.main()
