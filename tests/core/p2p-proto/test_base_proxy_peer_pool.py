import asyncio
import pytest

from p2p.tools.factories import SessionFactory

from trinity.protocol.common.events import (
    GetConnectedPeersRequest,
    GetConnectedPeersResponse,
    PeerJoinedEvent,
    PeerLeftEvent,
)
from trinity.tools.event_bus import mock_request_response

from tests.core.integration_test_helpers import (
    run_proxy_peer_pool,
)

TEST_NODES = tuple(SessionFactory.create_batch(4))


@pytest.mark.asyncio
async def test_can_instantiate_proxy_pool(event_bus):
    async with run_proxy_peer_pool(event_bus) as proxy_peer_pool:
        assert proxy_peer_pool is not None


@pytest.mark.parametrize(
    "response, expected_count",
    (
        (GetConnectedPeersResponse(tuple()), 0),
        (GetConnectedPeersResponse(TEST_NODES), 4),
    ),
)
@pytest.mark.asyncio
async def test_fetch_initial_peers(event_bus, response, expected_count):
    do_mock = mock_request_response(GetConnectedPeersRequest, response, event_bus)

    async with do_mock:
        async with run_proxy_peer_pool(event_bus) as proxy_peer_pool:
            peers = await proxy_peer_pool.fetch_initial_peers()
            assert len(peers) == expected_count


@pytest.mark.parametrize(
    "response, expected_count",
    (
        (GetConnectedPeersResponse(tuple()), 0),
        (GetConnectedPeersResponse(TEST_NODES), 4),
    ),
)
@pytest.mark.asyncio
async def test_get_peers(event_bus, response, expected_count):
    do_mock = mock_request_response(GetConnectedPeersRequest, response, event_bus)

    async with do_mock:
        async with run_proxy_peer_pool(event_bus) as proxy_peer_pool:
            peers = await proxy_peer_pool.get_peers()
            assert len(peers) == expected_count


@pytest.mark.asyncio
async def test_adds_new_peers(event_bus):

    do_mock = mock_request_response(
        GetConnectedPeersRequest,
        GetConnectedPeersResponse((TEST_NODES[0],)),
        event_bus,
    )
    async with do_mock:
        async with run_proxy_peer_pool(event_bus) as proxy_peer_pool:

            assert len(await proxy_peer_pool.get_peers()) == 1

            await event_bus.broadcast(PeerJoinedEvent(TEST_NODES[1]))
            # Give the peer a moment to pickup the peer
            await asyncio.sleep(0.01)

            assert len(await proxy_peer_pool.get_peers()) == 2


@pytest.mark.asyncio
async def test_removes_peers(event_bus):
    do_mock = mock_request_response(
        GetConnectedPeersRequest,
        GetConnectedPeersResponse(TEST_NODES[:2]),
        event_bus,
    )

    async with do_mock:
        async with run_proxy_peer_pool(event_bus) as proxy_peer_pool:

            assert len(await proxy_peer_pool.get_peers()) == 2

            await event_bus.broadcast(PeerLeftEvent(TEST_NODES[0]))
            # Give the peer a moment to remove the peer
            await asyncio.sleep(0.01)

            peers = await proxy_peer_pool.get_peers()
            assert len(peers) == 1
            assert peers[0].session == TEST_NODES[1]
