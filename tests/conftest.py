import pytest_asyncio

from backend.moss_client import PrecedentStore

_store = None


@pytest_asyncio.fixture(scope="session")
async def store():
    """One warmed PrecedentStore for the whole test session (indexes are cached)."""
    global _store
    if _store is None:
        _store = PrecedentStore()
        await _store.ensure_ready()
    return _store
