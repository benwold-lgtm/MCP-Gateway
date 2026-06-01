"""Unit tests for SqliteDeviceStore."""

import pytest
import pytest_asyncio

from device_mcp_gateway.storage.sqlite_store import SqliteDeviceStore


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_devices.db")


@pytest_asyncio.fixture
async def store(db_path):
    s = SqliteDeviceStore(db_path=db_path)
    await s.initialize()
    return s


@pytest.mark.asyncio
async def test_save_and_load(store):
    await store.save("my-device", {
        "base_url": "http://device.local",
        "spec_url": None,
        "transport": "sse",
        "auth_type": "api_key",
        "auth_config": {"type": "api_key", "api_key": "secret", "header_name": "X-API-Key"},
    })
    records = await store.load_all()
    assert len(records) == 1
    r = records[0]
    assert r["hostname"] == "my-device"
    assert r["base_url"] == "http://device.local"
    assert r["auth_config"]["api_key"] == "secret"


@pytest.mark.asyncio
async def test_upsert_replaces_existing(store):
    await store.save("dev", {"base_url": "http://a.local", "transport": "sse",
                              "auth_type": None, "auth_config": None})
    await store.save("dev", {"base_url": "http://b.local", "transport": "http",
                              "auth_type": None, "auth_config": None})
    records = await store.load_all()
    assert len(records) == 1
    assert records[0]["base_url"] == "http://b.local"
    assert records[0]["transport"] == "http"


@pytest.mark.asyncio
async def test_delete_removes_record(store):
    await store.save("dev", {"base_url": "http://x.local", "transport": "sse",
                              "auth_type": None, "auth_config": None})
    await store.delete("dev")
    records = await store.load_all()
    assert records == []


@pytest.mark.asyncio
async def test_load_empty_store(store):
    records = await store.load_all()
    assert records == []


@pytest.mark.asyncio
async def test_multiple_devices(store):
    for i in range(3):
        await store.save(f"dev-{i}", {"base_url": f"http://dev-{i}.local",
                                       "transport": "sse", "auth_type": None, "auth_config": None})
    records = await store.load_all()
    assert len(records) == 3
    hostnames = {r["hostname"] for r in records}
    assert hostnames == {"dev-0", "dev-1", "dev-2"}
