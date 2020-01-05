import random
from typing import Sequence, Set, Tuple, Dict, List

import trio
from cancel_token import CancelToken
from eth_keys import datatypes
from lahja import EndpointAPI

from p2p import constants
from p2p.abc import AddressAPI, NodeAPI
from p2p.aurora.util import calculate_distance, aurora_pick, assumed_malicious_node_number, quantified_mistake, \
    optimize_distance_with_mistake, calculate_correctness_indicator, aurora_put, optimum, aurora_head
from p2p.discovery import DiscoveryService


class AuroraDiscoveryService(DiscoveryService):

    def __init__(self,
                 privkey: datatypes.PrivateKey,
                 address: AddressAPI,
                 bootstrap_nodes: Sequence[NodeAPI],
                 event_bus: EndpointAPI,
                 socket: trio.socket.SocketType) -> None:
        super().__init__(privkey, address, bootstrap_nodes, event_bus, socket)

    async def aurora_walk(self, entry_node: NodeAPI,
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

        while iteration < distance:

            self._send_find_node(current_node_in_walk, self.random_kademlia_node_id())
            candidates = await self.wait_neighbours(current_node_in_walk)

            last_neighbours_response_size = len(candidates)
            # todo what about the known ones but not available? this should consider it
            num_of_already_known_peers = len(collected_nodes_set & set(candidates))
            mistake = quantified_mistake(network_size,
                                         malicious_nodes_number_approx,
                                         last_neighbours_response_size,
                                         num_of_already_known_peers)
            accumulated_mistake += mistake
            if accumulated_mistake >= standard_mistakes_threshold:
                break

            distance = optimize_distance_with_mistake(distance, mistake)
            current_node_in_walk = aurora_pick(set(candidates), collected_nodes_set)
            collected_nodes_set.update(candidates)
            if network_size == len(collected_nodes_set):
                break
            iteration += 1
        correctness_indicator = calculate_correctness_indicator(accumulated_mistake, standard_mistakes_threshold)
        # todo return chain head instead of key later on
        head_hash = await aurora_head(current_node_in_walk)
        return correctness_indicator, head_hash, collected_nodes_set

    def aurora_tally(self,
                     entry_node: NodeAPI,
                     standard_mistakes_threshold: int,
                     network_size: int,
                     neighbours_response_size: int,
                     num_of_walks: int):
        correctness_dict: Dict[any, List[float]] = {}
        correctness_indicator, pubkey, collected_nodes_set = self.aurora_walk(
            entry_node,
            network_size,
            neighbours_response_size,
            standard_mistakes_threshold)
        if correctness_indicator == 0:
            # stuck in clique
            self.logger.warning("Clique detected during p2p discovery!")
            return None
        correctness_dict = aurora_put(correctness_dict,
                                      pubkey,
                                      correctness_indicator)
        # starting from 1 since we already made one walk
        for _ in range(1, num_of_walks):
            current_node = aurora_pick(collected_nodes_set, set())
            correctness_indicator, pubkey, collected_nodes_set = self.aurora_walk(
                current_node,
                network_size,
                neighbours_response_size,
                standard_mistakes_threshold)
            correctness_dict = aurora_put(correctness_dict,
                                          pubkey,
                                          correctness_indicator)
        return optimum(correctness_dict)

    @staticmethod
    def random_kademlia_node_id() -> int:
        return random.randint(0, constants.KADEMLIA_MAX_NODE_ID)
