from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

import networkx as nx
import structlog
from eth_utils import to_checksum_address
from networkx import DiGraph

from pathfinding_service.config import (
    DEFAULT_SETTLE_TO_REVEAL_TIMEOUT_RATIO,
    DIVERSITY_PEN_DEFAULT,
    FEE_PEN_DEFAULT,
)
from pathfinding_service.model.channel_view import ChannelView
from pathfinding_service.model.feedback import RouteFeedback
from raiden.messages import UpdatePFS
from raiden.utils.typing import Address, ChannelID, TokenAmount, TokenNetworkAddress

log = structlog.get_logger(__name__)


class Path:
    def __init__(self, G: DiGraph, nodes: List[Address], value: float):
        self.G = G
        self.nodes = nodes
        self.value = value

    @property
    def edge_attrs(self) -> Iterable[dict]:
        return (self.G[node1][node2] for node1, node2 in zip(self.nodes[:-1], self.nodes[1:]))

    def to_dict(self) -> dict:
        fee = sum(edge["view"].fee(self.value) for edge in self.edge_attrs)
        return dict(path=[to_checksum_address(node) for node in self.nodes], estimated_fee=fee)

    @property
    def is_valid(self) -> bool:
        """ Check capacity and settle timeout

        Capacity: The capacity for the last channel must be at least
        the payment value. The previous channel's capacity has to be larger
        than value + last channel's capacity, etc.

        Settle timeout: The raiden client will not forward payments if the
        channel over which they receive has a too low settle_timeout. So we
        should not use such routes. See
        https://github.com/raiden-network/raiden-services/issues/5.
        """
        required_capacity = self.value
        for edge in reversed(list(self.edge_attrs)):
            # check capacity
            if edge["view"].capacity < required_capacity:
                return False
            required_capacity += edge["view"].fee(self.value)

            # check if settle_timeout / reveal_timeout >= default ratio
            ratio = edge["view"].settle_timeout / edge["view"].reveal_timeout
            if ratio < DEFAULT_SETTLE_TO_REVEAL_TIMEOUT_RATIO:
                return False
        return True


class TokenNetwork:
    """ Manages a token network for pathfinding. """

    def __init__(self, token_network_address: TokenNetworkAddress):
        """ Initializes a new TokenNetwork. """

        self.address = token_network_address
        self.channel_id_to_addresses: Dict[ChannelID, Tuple[Address, Address]] = dict()
        self.G = DiGraph()
        self.max_relative_fee = 0
        self.feedback: List[RouteFeedback] = []

    def __repr__(self) -> str:
        return (
            f"<TokenNetwork address = {self.address} "
            f"num_channels = {len(self.channel_id_to_addresses)}>"
        )

    #
    # Contract event listener functions
    #

    def handle_channel_opened_event(
        self,
        channel_identifier: ChannelID,
        participant1: Address,
        participant2: Address,
        settle_timeout: int,
    ) -> List[ChannelView]:
        """ Register the channel in the graph, add participents to graph if necessary.

        Corresponds to the ChannelOpened event. Called by the contract event listener. """
        views = [
            ChannelView(
                token_network_address=self.address,
                channel_id=channel_identifier,
                participant1=participant1,
                participant2=participant2,
                settle_timeout=settle_timeout,
                deposit=TokenAmount(0),
            ),
            ChannelView(
                token_network_address=self.address,
                channel_id=channel_identifier,
                participant1=participant2,
                participant2=participant1,
                settle_timeout=settle_timeout,
                deposit=TokenAmount(0),
            ),
        ]

        for cv in views:
            self.add_channel_view(cv)

        return views

    def add_channel_view(self, channel_view: ChannelView) -> None:
        # Choosing which direction to add by execution order is not very
        # robust. We might want to change this to either
        # * participant1 < participant2 or
        # * same as in contract (which would require an additional attribute on ChannelView)
        if channel_view.channel_id not in self.channel_id_to_addresses:
            self.channel_id_to_addresses[channel_view.channel_id] = (
                channel_view.participant1,
                channel_view.participant2,
            )
        self.G.add_edge(channel_view.participant1, channel_view.participant2, view=channel_view)

    def handle_channel_new_deposit_event(
        self, channel_identifier: ChannelID, receiver: Address, total_deposit: TokenAmount
    ) -> Optional[ChannelView]:
        """ Register a new balance for the beneficiary.

        Corresponds to the ChannelNewDeposit event. Called by the contract event listener. """

        try:
            participant1, participant2 = self.channel_id_to_addresses[channel_identifier]
            if receiver == participant1:
                channel_view = self.G[participant1][participant2]["view"]
            elif receiver == participant2:
                channel_view = self.G[participant2][participant1]["view"]
            else:
                log.error("Receiver in ChannelNewDeposit does not fit the internal channel")
                return None
        except KeyError:
            log.error(
                "Received ChannelNewDeposit event for unknown channel",
                channel_identifier=channel_identifier,
            )
            return None

        channel_view.update_deposit(total_deposit=total_deposit)
        return channel_view

    def handle_channel_closed_event(self, channel_identifier: ChannelID) -> None:
        """ Close a channel. This doesn't mean that the channel is settled yet, but it cannot
        transfer any more.

        Corresponds to the ChannelClosed event. Called by the contract event listener. """

        try:
            # we need to unregister the channel_id here
            participant1, participant2 = self.channel_id_to_addresses.pop(channel_identifier)

            self.G.remove_edge(participant1, participant2)
            self.G.remove_edge(participant2, participant1)
        except KeyError:
            log.error(
                "Received ChannelClosed event for unknown channel",
                channel_identifier=channel_identifier,
            )

    def get_channel_views_for_partner(
        self,
        channel_identifier: ChannelID,
        updating_participant: Address,
        other_participant: Address,
    ) -> Tuple[ChannelView, ChannelView]:
        assert channel_identifier in self.channel_id_to_addresses

        # Get the channel views from the perspective of the updating participant
        channel_view_to_partner = self.G[updating_participant][other_participant]["view"]
        channel_view_from_partner = self.G[other_participant][updating_participant]["view"]

        return channel_view_to_partner, channel_view_from_partner

    def handle_channel_balance_update_message(
        self,
        message: UpdatePFS,
        updating_capacity_partner: TokenAmount,
        other_capacity_partner: TokenAmount,
    ) -> None:
        """ Sends Capacity Update to PFS including the reveal timeout """
        channel_view_to_partner, channel_view_from_partner = self.get_channel_views_for_partner(
            channel_identifier=message.canonical_identifier.channel_identifier,
            updating_participant=message.updating_participant,
            other_participant=message.other_participant,
        )
        channel_view_to_partner.update_capacity(
            nonce=message.updating_nonce,
            capacity=min(message.updating_capacity, other_capacity_partner),
            reveal_timeout=message.reveal_timeout,
            mediation_fee=message.mediation_fee,
        )
        channel_view_from_partner.update_capacity(
            nonce=message.other_nonce,
            capacity=min(message.other_capacity, updating_capacity_partner),
        )

    @staticmethod
    def edge_weight(
        visited: Dict[ChannelID, float],
        attr: Dict[str, Any],
        attr_backwards: Dict[str, Any],
        amount: TokenAmount,
        fee_penalty: float,
    ) -> float:
        view: ChannelView = attr["view"]
        view_from_partner: ChannelView = attr_backwards["view"]
        diversity_weight = visited.get(view.channel_id, 0)
        fee_weight = view.fee(amount) / 1e18 * fee_penalty
        no_refund_weight = 0
        if view_from_partner.capacity < int(float(amount) * 1.1):
            no_refund_weight = 1
        return 1 + diversity_weight + fee_weight + no_refund_weight

    def _get_single_path(
        self,
        source: Address,
        target: Address,
        value: TokenAmount,
        visited: Dict[ChannelID, float],
        disallowed_paths: List[List[Address]],
        fee_penalty: float,
    ) -> Optional[Path]:
        # update edge weights
        for node1, node2 in self.G.edges():
            edge = self.G[node1][node2]
            backwards_edge = self.G[node2][node1]
            edge["weight"] = self.edge_weight(visited, edge, backwards_edge, value, fee_penalty)

        # find next path
        all_paths: Iterable[List[Address]] = nx.shortest_simple_paths(
            self.G, source, target, weight="weight"
        )
        try:
            # skip duplicates and invalid paths
            path = next(
                p
                for p in (Path(self.G, nodes, value) for nodes in all_paths)
                if p.is_valid and p.nodes not in disallowed_paths
            )
            return path
        except StopIteration:
            return None

    def get_paths(
        self,
        source: Address,
        target: Address,
        value: TokenAmount,
        max_paths: int,
        diversity_penalty: float = DIVERSITY_PEN_DEFAULT,
        fee_penalty: float = FEE_PEN_DEFAULT,
    ) -> List[dict]:
        """ Find best routes according to given preferences

        value: Amount of transferred tokens. Used for capacity checks
        diversity_penalty: One previously used channel is as bad as X more hops
        fee_penalty: One RDN in fees is as bad as X more hops
        """
        visited: Dict[ChannelID, float] = defaultdict(lambda: 0)
        paths: List[Path] = []

        while len(paths) < max_paths:
            path = self._get_single_path(
                source=source,
                target=target,
                value=value,
                visited=visited,
                disallowed_paths=[p.nodes for p in paths],
                fee_penalty=fee_penalty,
            )
            if path is None:
                break
            paths.append(path)

            # update visited penalty dict
            for edge in path.edge_attrs:
                channel_id = edge["view"].channel_id
                visited[channel_id] += diversity_penalty

        return [p.to_dict() for p in paths]
