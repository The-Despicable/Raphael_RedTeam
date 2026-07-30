import argparse
import asyncio
import uvicorn

try:
    from mcp_hub.core.server import MCPServer
    from mcp_hub.core.transport import StdioTransport
except ImportError:
    from mcp_hub.core.server import MCPServer
    from mcp_hub.core.transport import StdioTransport


def create_app():
    server = MCPServer()
    return server.app


def main():
    parser = argparse.ArgumentParser(description="Raphael 2.0 MCP Hub")
    parser.add_argument("--transport", choices=["http", "stdio"], default="http",
                        help="Transport mode (default: http)")
    parser.add_argument("--host", default="0.0.0.0", help="HTTP bind host")
    parser.add_argument("--port", type=int, default=8000, help="HTTP bind port")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes")
    args = parser.parse_args()

    if args.transport == "http":
        uvicorn.run(
            "main:create_app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            factory=True,
            log_level="info",
        )
    elif args.transport == "stdio":
        server = MCPServer()
        transport = StdioTransport(server.mcp_handler if hasattr(server, 'mcp_handler') else None)
        asyncio.run(transport.serve())


if __name__ == "__main__":
    main()
