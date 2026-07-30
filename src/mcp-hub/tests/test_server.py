import pytest
from httpx import AsyncClient, ASGITransport
from mcp_hub.core.server import MCPServer


@pytest.fixture
def app():
    server = MCPServer()
    return server.app


@pytest.mark.asyncio
async def test_health(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        resp = await cl.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "tools_loaded" in data
        assert "categories" in data


@pytest.mark.asyncio
async def test_mcp_tools_list_no_auth(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        resp = await cl.post("/mcp", json={"method": "tools.list", "id": 1})
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mcp_tools_list_with_auth(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        resp = await cl.post(
            "/mcp",
            json={"method": "tools.list", "id": 1},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code in (200, 401)


@pytest.mark.asyncio
async def test_mcp_unknown_method(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        resp = await cl.post(
            "/mcp",
            json={"method": "unknown.method", "id": 1},
            headers={"Authorization": "Bearer raphael-admin-key-change-me"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "result" in data


@pytest.mark.asyncio
async def test_resources_list(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        resp = await cl.post(
            "/mcp",
            json={"method": "resources.list", "id": 1},
            headers={"Authorization": "Bearer raphael-admin-key-change-me"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "result" in data


@pytest.mark.asyncio
async def test_prompts_list(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        resp = await cl.post(
            "/mcp",
            json={"method": "prompts.list", "id": 1},
            headers={"Authorization": "Bearer raphael-admin-key-change-me"},
        )
        assert resp.status_code == 200
