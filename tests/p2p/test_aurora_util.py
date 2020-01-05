from typing import AsyncIterator, cast

import pytest
from eth.chains.base import MiningChain
from eth.db.atomic import AtomicDB
from eth.tools.builder.chain import latest_mainnet_at, disable_pow_check, genesis
from ethpm.tools.builder import build
from pytest import approx
from p2p.aurora.util import calculate_distance, _distance_expectation_matrix_markov, \
    _distance_transition_matrix_markov, optimum, quantified_mistake, aurora_head
from tests.core.integration_test_helpers import run_proxy_peer_pool, load_mining_chain, load_fixture_db, DBFixture
from trinity.db.eth1.header import AsyncHeaderDB
from trinity.protocol.common.peer_pool_event_bus import TProxyPeer
from trinity.protocol.eth.peer import ETHPeer
from trinity.tools.factories import ETHPeerPairFactory, ChainContextFactory

absolute_tolerance = 10e-2

@pytest.fixture
def bob_chain():
    chain = build(
        MiningChain,
        latest_mainnet_at(0),
        disable_pow_check(),
        genesis(),
    )
    return chain


@pytest.fixture
def alice_chain(bob_chain):
    bob_genesis = bob_chain.headerdb.get_canonical_block_header_by_number(0)

    chain = build(
        MiningChain,
        latest_mainnet_at(0),
        disable_pow_check(),
        genesis(params={"timestamp": bob_genesis.timestamp}),
    )
    return chain

@pytest.fixture
def leveldb_20():
    yield from load_fixture_db(DBFixture.TWENTY_POW_HEADERS)

# todo duplicate from config test
@pytest.fixture
def chaindb_20(leveldb_20):
    chain = load_mining_chain(AtomicDB(leveldb_20))
    assert chain.chaindb.get_canonical_head().block_number == 20
    return chain.chaindb


@pytest.fixture
def chaindb_fresh():
    chain = load_mining_chain(AtomicDB())
    assert chain.chaindb.get_canonical_head().block_number == 0
    return chain.chaindb


@pytest.fixture
async def client_and_server(alice_chain, bob_chain):
    pair_factory = ETHPeerPairFactory(
        alice_client_version='alice',
        alice_peer_context=ChainContextFactory(headerdb=AsyncHeaderDB(alice_chain.headerdb.db)),
        bob_client_version='bob',
        bob_peer_context=ChainContextFactory(headerdb=AsyncHeaderDB(bob_chain.headerdb.db)),
    )
    async with pair_factory as (alice, bob):
        yield alice, bob


def assert_matrices_equal(expected, result):
    # matrices have to be same size
    assert len(expected) == len(result) and len(expected[0]) == len(result[0])
    for row_index in range(len(result)):
        assert result[row_index] == approx(expected[row_index], abs=absolute_tolerance)


@pytest.mark.parametrize("params, expected", [
    ((5, 3, 2), 4.325),
    ((52, 26, 5), 38.947),
    ((100, 30, 10), 38.535),
    # testing response_size being bigger then network_size
    ((5, 3, 10), 1),
    # test disabled since it is computationally demanding and takes longer time
    # ((1000, 499, 40), 166.9329)
])
def test_aurora_distance(params, expected):
    assert calculate_distance(*params) == approx(expected, abs=absolute_tolerance)


def test_draw_amount_expectation_matrix_markov():
    expected = [[1.111, 0.95238, 2.26190],
                [0, 1.42857, 2.14286],
                [0, 0, 2.5]]
    transition_matrix = _distance_transition_matrix_markov(5, 3, 2)
    result_matrix = _distance_expectation_matrix_markov(transition_matrix)
    assert_matrices_equal(expected, result_matrix)


def test_draw_amount_transition_matrix_markov():
    expected = [[0.10000,   0.60000,   0.30000,   0.00000],
                [0.00000,   0.30000,   0.60000,   0.10000],
                [0.00000,   0.00000,   0.60000,   0.40000],
                [0.00000,   0.00000,   0.00000,   1.00000]]
    result = _distance_transition_matrix_markov(5, 3, 2)
    assert_matrices_equal(expected, result)


@pytest.mark.parametrize("map, expected", [
    ({
        'a': [0.6, 0.51, 0.55],
        'b': [0.91]
    }, ('b', 0.753)),
    ({
        'a': [0.6, 0.51, 0.55],
        'b': [0.4]
    }, ('a', 0.508)),
    ({
        'a': [0.9, 0.9, 0.9],
        'b': [0.91]
    }, ('a', 2.187)),
])
def test_optimum(map, expected):
    result_key, result_value = optimum(map)
    expected_key, expected_value = expected
    assert result_key == expected_key
    assert result_value == approx(expected_value, abs=absolute_tolerance)


@pytest.mark.parametrize("total_size, success_states_in_population, sample_size, observed_successes, expected", [
    (21, 5, 3, 3, 6.823529),
    (10, 5, 3, 3, 1),
    (100, 49, 16, 0, 0),
    (100, 1, 5, 0, 0),
])
def test_quantified_mistake(total_size, success_states_in_population, sample_size, observed_successes, expected):
    assert quantified_mistake(total_size,
                              success_states_in_population,
                              sample_size,
                              observed_successes) \
           == approx(expected, abs=absolute_tolerance)


async def test_aurora_head(client_and_server, event_bus):
    alice, bob = client_and_server
    bob: ETHPeer = cast(ETHPeer, bob)
    alice: ETHPeer = cast(ETHPeer, alice)

    async with run_proxy_peer_pool(event_bus) as proxy_peer_pool:
        bob_proxy_peer = await proxy_peer_pool.ensure_proxy_peer(bob.session)

        async def yield_peer() -> AsyncIterator[TProxyPeer]:
            yield bob_proxy_peer

        proxy_peer_pool.stream_existing_and_joining_peers = yield_peer

    assert aurora_head(alice.session.remote, event_bus, proxy_peer_pool, None) == bob.head_info.head_hash



