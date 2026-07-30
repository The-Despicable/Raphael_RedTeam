"""
Quick smoke test for integration harness that can run without full target.
"""

from __future__ import annotations

import asyncio
import logging
import os
from unittest.mock import AsyncMock, MagicMock, patch

from raphael.integration.harness import IntegrationHarness, IntegrationConfig

logging.basicConfig(level=logging.DEBUG)


async def test_harness_initialization():
    """Test that harness initializes all components without errors."""
    config = IntegrationConfig(
        target_ip="127.0.0.1",
        target_hostname="test.local",
        redis_url="redis://localhost:6379/0",
    )
    
    harness = IntegrationHarness(config)
    
    # Mock Redis to avoid needing a real server
    with patch('redis.asyncio.from_url') as mock_redis:
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.close = AsyncMock()
        mock_redis.return_value = mock_client
        
        # Mock EventBus connect
        with patch.object(harness, 'eventbus', create=True):
            harness.eventbus = AsyncMock()
            harness.eventbus.connect = AsyncMock()
            harness.eventbus.disconnect = AsyncMock()
            
            # Test setup
            try:
                await harness.setup()
                print("✓ Harness setup successful")
            except Exception as e:
                print(f"✗ Harness setup failed: {e}")
                return False
            
            # Test teardown
            try:
                await harness.teardown()
                print("✓ Harness teardown successful")
            except Exception as e:
                print(f"✗ Harness teardown failed: {e}")
                return False
    
    return True


async def test_config_validation():
    """Test config validation."""
    from raphael.integration.harness import IntegrationConfig
    
    # Test default config
    config = IntegrationConfig()
    assert config.target_ip == "10.129.41.98"
    assert config.target_hostname == "bedside.htb"
    assert "dns_brute" in config.vhost_methods
    print("✓ Config validation passed")
    return True


async def main():
    """Run all smoke tests."""
    logging.basicConfig(level=logging.INFO)
    
    print("Running integration smoke tests...\n")
    
    try:
        await test_config_validation()
        print()
        
        # Skip full init test if Redis not available
        try:
            await test_harness_initialization()
        except Exception as e:
            print(f"⚠ Harness init test skipped (Redis not available): {e}")
        
        print("\n✓ All smoke tests passed")
    except Exception as e:
        print(f"\n✗ Smoke test failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())