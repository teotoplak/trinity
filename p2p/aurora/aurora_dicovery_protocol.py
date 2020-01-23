import random
from typing import Sequence, Set, Tuple, Dict, List

import trio
from eth_keys import datatypes
from lahja import EndpointAPI

from p2p import constants
from p2p.abc import AddressAPI, NodeAPI
from p2p.aurora.util import calculate_distance, aurora_pick, assumed_malicious_node_number, quantified_mistake, \
    optimize_distance_with_mistake, calculate_correctness_indicator, aurora_put, optimum
from p2p.constants import KADEMLIA_BUCKET_SIZE
from p2p.discovery import DiscoveryService
from trinity.constants import TO_NETWORKING_BROADCAST_CONFIG
from trinity.events import ShutdownRequest
from trinity.protocol.common.events import ConnectToNodeCommand
from trinity.protocol.eth.peer import ETHProxyPeerPool


class CliqueDetectedError(Exception):
    """Possible malicious network"""
    pass


class AuroraDiscoveryService(DiscoveryService):

    def __init__(self,
                 privkey: datatypes.PrivateKey,
                 address: AddressAPI,
                 bootstrap_nodes: Sequence[NodeAPI],
                 event_bus: EndpointAPI,
                 socket: trio.socket.SocketType,
                 proxy_peer_pool: ETHProxyPeerPool = None,
                 network_size: int = 2000,
                 mistake_threshold: int = 50,
                 num_of_walks: int = 1) -> None:
        super().__init__(privkey, address, bootstrap_nodes, event_bus, socket)
        self.network_size = network_size
        self.mistake_threshold = mistake_threshold
        self.num_of_walks = num_of_walks
        self.proxy_peer_pool = proxy_peer_pool

    # todo should not extend this method, it's a quick hack
    async def lookup_random(self) -> Tuple[NodeAPI, ...]:
        self.logger.info("Aurora Component lookup started...")
        entry_node: NodeAPI = self.routing.get_random_nodes(1)
        try:
            await self.aurora_tally(entry_node,
                                    self.mistake_threshold,
                                    self.network_size,
                                    KADEMLIA_BUCKET_SIZE,
                                    self.num_of_walks)
        except CliqueDetectedError:
            self.logger.warning("Clique detected during p2p discovery!")
            await self._event_bus.broadcast(ShutdownRequest("Possible malicious network - exiting!"))

    async def aurora_walk(self,
                          entry_node: NodeAPI,
                          network_size: int,
                          neighbours_response_size: int,
                          standard_mistakes_threshold: int) -> Tuple[float, any, Set[NodeAPI]]:

        malicious_nodes_number_approx = assumed_malicious_node_number(network_size)
        distance = calculate_distance(network_size,
                                      malicious_nodes_number_approx,
                                      neighbours_response_size)
        collected_nodes_set: Set[NodeAPI] = set()
        iteration = 0
        accumulated_mistake = 0
        current_node_in_walk: NodeAPI = entry_node

        self.logger.debug2(f"Starting Aurora walk - distance: {distance:.2f}, "
                           f"mistake_threshold: {standard_mistakes_threshold}")

        while iteration < distance:

            self._send_find_node(current_node_in_walk, self.random_kademlia_node_id())
            candidates = await self.wait_neighbours(current_node_in_walk)

            last_neighbours_response_size = len(candidates)
            collected_nodes_set.update(candidates)
            num_of_collected_total = len(collected_nodes_set)
            # todo what about the known ones but not available? this should consider it
            num_of_already_known_peers = len(collected_nodes_set & set(candidates))
            mistake = quantified_mistake(network_size,
                                         num_of_collected_total,
                                         last_neighbours_response_size,
                                         num_of_already_known_peers)
            accumulated_mistake += mistake
            distance = optimize_distance_with_mistake(distance, mistake)
            current_node_in_walk = aurora_pick(set(candidates), collected_nodes_set)
            if network_size == len(collected_nodes_set):
                break
            iteration += 1

            self.logger.debug2(f"iter: {iteration} | distance: {distance:.2f} | "
                               f"{num_of_already_known_peers}/{last_neighbours_response_size} known peers | "
                               f"total_mistake: {accumulated_mistake:.2f} (+{mistake:.2f})")

            if accumulated_mistake >= standard_mistakes_threshold:
                self.logger.debug2("Aurora is assuming malicious a activity: exiting the network!")
                return 0, None, collected_nodes_set

        correctness_indicator = calculate_correctness_indicator(accumulated_mistake, standard_mistakes_threshold)
        try:
            head_hash = await self.aurora_head(current_node_in_walk,
                                               self._event_bus,
                                               self.proxy_peer_pool,
                                               60)
        except TimeoutError:
            self.logger.warning(f"Could not connect to a peer {current_node_in_walk.pubkey} over proxy pool - timeout")
            raise ConnectionRefusedError

        return correctness_indicator, head_hash, collected_nodes_set

    async def aurora_tally(self,
                           entry_node: NodeAPI,
                           standard_mistakes_threshold: int,
                           network_size: int,
                           neighbours_response_size: int,
                           num_of_walks: int):
        correctness_dict: Dict[any, List[float]] = {}
        iteration = 0
        current_node = entry_node
        while iteration < num_of_walks:
            try:
                correctness_indicator, pubkey, collected_nodes_set = await self.aurora_walk(
                    current_node,
                    network_size,
                    neighbours_response_size,
                    standard_mistakes_threshold)
            except ConnectionRefusedError:
                self.logger.warning(f"Executing additional Aurora walk")
                continue
            if correctness_indicator == 0:
                # stuck in clique
                raise CliqueDetectedError

            correctness_dict = aurora_put(correctness_dict,
                                          pubkey,
                                          correctness_indicator)
            current_node = aurora_pick(collected_nodes_set, set())
            iteration += 1
        return optimum(correctness_dict)

    @staticmethod
    async def aurora_head(node: NodeAPI,
                          event_bus: EndpointAPI,
                          proxy_peer_pool: ETHProxyPeerPool,
                          timeout: int = 60):
        """ Returns the head hash from a remote node

        Raises TimeoutError if proxy peer couldn't fetch the peer in provided time period
        """
        await event_bus.broadcast(
            ConnectToNodeCommand(node),
            TO_NETWORKING_BROADCAST_CONFIG
        )
        proxy_peer = await proxy_peer_pool.get_existing_or_joining_peer(node.id, timeout)
        return await proxy_peer.eth_api.get_head_hash()

    @staticmethod
    def random_kademlia_node_id() -> int:
        return random.randint(0, constants.KADEMLIA_MAX_NODE_ID)
