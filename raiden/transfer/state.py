# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
import random
from collections import defaultdict
from dataclasses import (
    dataclass,
    field,
    InitVar,
)
from enum import Enum

import networkx

from raiden.constants import UINT256_MAX, UINT64_MAX
from raiden.encoding.format import buffer_for
from raiden.encoding import messages
from raiden.transfer.architecture import State
from raiden.transfer.utils import hash_balance_data
from raiden.utils import sha3, typing

SecretHashToLock = typing.Dict[typing.SecretHash, 'HashTimeLockState']
SecretHashToPartialUnlockProof = typing.Dict[typing.SecretHash, 'UnlockPartialProofState']

CHANNEL_STATE_CLOSED = 'closed'
CHANNEL_STATE_CLOSING = 'waiting_for_close'
CHANNEL_STATE_OPENED = 'opened'
CHANNEL_STATE_SETTLED = 'settled'
CHANNEL_STATE_SETTLING = 'waiting_for_settle'
CHANNEL_STATE_UNUSABLE = 'channel_unusable'

CHANNEL_ALL_VALID_STATES = (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
)

CHANNEL_STATES_PRIOR_TO_CLOSED = (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSING,
)

CHANNEL_AFTER_CLOSE_STATES = (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_SETTLED,
)

NODE_NETWORK_UNKNOWN = 'unknown'
NODE_NETWORK_UNREACHABLE = 'unreachable'
NODE_NETWORK_REACHABLE = 'reachable'


def balanceproof_from_envelope(envelope_message):
    return BalanceProofSignedState(
        envelope_message.nonce,
        envelope_message.transferred_amount,
        envelope_message.locked_amount,
        envelope_message.locksroot,
        envelope_message.token_network_address,
        envelope_message.channel_identifier,
        envelope_message.message_hash,
        envelope_message.signature,
        envelope_message.sender,
        envelope_message.chain_id,
    )


def lockstate_from_lock(lock):
    return HashTimeLockState(
        lock.amount,
        lock.expiration,
        lock.secrethash,
    )


def message_identifier_from_prng(prng):
    return prng.randint(0, UINT64_MAX)


@dataclass
class InitiatorTask:
    token_network_identifier: typing.TokenNetworkID
    manager_state: 'InitiatorTransferState'


@dataclass
class MediatorTask:
    token_network_identifier: typing.TokenNetworkID
    mediator_state: 'MediatorTransferState'


@dataclass
class TargetTask:
    token_network_identifier: typing.TokenNetworkID
    channel_identifier: typing.ChannelID
    target_state: 'TargetTransferState'


@dataclass
class ChainState(State):
    """ Umbrella object that stores the per blockchain state.

    For each registry smart contract there must be a payment network. Within the
    payment network the existing token networks and channels are registered.

    TODO: Split the node specific attributes to a "NodeState" class
    """

    pseudo_random_generator: random.Random
    block_number: typing.BlockNumber
    our_address: typing.Address
    chain_id: typing.ChainID
    identifiers_to_paymentnetworks: dict = field(default_factory=dict)
    nodeaddresses_to_networkstates: dict = field(default_factory=dict)
    pending_transactions: list = field(default_factory=list)
    queueids_to_queues: dict = field(default_factory=dict)
    payment_mapping: 'PaymentMappingState' = field(
        default_factory=lambda: PaymentMappingState(),
    )


@dataclass
class PaymentNetworkState(State):
    address: typing.Address
    token_network_list: InitVar[typing.List['TokenNetworkState']]
    tokenidentifiers_to_tokennetworks: dict = field(init=False)
    tokenaddresses_to_tokennetworks: dict = field(init=False)

    def __post_init__(self, token_network_list):
        self.tokenidentifiers_to_tokennetworks = {
            token_network.address: token_network
            for token_network in token_network_list
        }
        self.tokenaddresses_to_tokennetworks = {
            token_network.token_address: token_network
            for token_network in token_network_list
        }


@dataclass
class TokenNetworkState(State):
    address: typing.Address
    token_address: typing.Address
    network_graph: 'TokenNetworkGraphState' = field(
        default_factory=lambda: TokenNetworkGraphState(),  # pylint: disable=unnecessary-lambda
    )
    channelidentifiers_to_channels: dict = field(default_factory=dict)
    partneraddresses_to_channels: defaultdict(dict) = field(
        default_factory=lambda: defaultdict(dict),
    )


# This is necessary for the routing only, maybe it should be transient state
# outside of the state tree.
@dataclass
class TokenNetworkGraphState(State):
    """ Graph for path finding. """
    network: networkx.Graph = field(default_factory=networkx.Graph)
    channel_identifier_to_participants: dict = field(default_factory=dict)


@dataclass
class PaymentMappingState(State):
    """ Global map from secrethash to a transfer task.

    This mapping is used to quickly dispatch state changes by secrethash, for
    those that dont have a balance proof, e.g. SecretReveal.

    This mapping forces one task per secrethash, assuming that secrethash collision
    is unlikely. Features like token swaps, that span multiple networks, must
    be encapsulated in a single task to work with this structure.
    """

    # Because of retries, there may be multiple transfers for the same payment,
    # IOW there may be more than one task for the same transfer identifier. For
    # this reason the mapping uses the secrethash as key.
    #
    # Because token swaps span multiple token networks, the state of the
    # payment task is kept in this mapping, instead of inside an arbitrary
    # token network.
    secrethashes_to_task: dict = field(default_factory=dict)


@dataclass
class RouteState(State):
    node_address: typing.Address
    channel_identifier: typing.ChannelID


@dataclass
class BalanceProofUnsignedState(State):
    """ Balance proof from the local node. """

    nonce: int
    transferred_amount: typing.TokenAmount
    locked_amount: typing.TokenAmount
    locksroot: typing.Locksroot
    token_network_identifier: typing.Address
    channel_identifier: typing.ChannelID
    chain_id: typing.ChainID

    @property
    def balance_hash(self):
        return hash_balance_data(
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )


@dataclass
class BalanceProofSignedState(State):
    """ Balance proof from the partern.

    This balance proof can be used on-chain to resolve disputes.
    """

    nonce: int
    transferred_amount: typing.TokenAmount
    locked_amount: typing.TokenAmount
    locksroot: typing.Locksroot
    token_network_identifier: typing.Address
    channel_identifier: typing.ChannelID
    message_hash: typing.Keccak256
    signature: typing.Signature
    sender: typing.Address
    chain_id: typing.ChainID

    @property
    def balance_hash(self):
        return hash_balance_data(
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )


@dataclass
class HashTimeLockState(State):
    amount: typing.TokenAmount
    expiration: typing.BlockNumber
    secrethash: typing.Keccak256
    encoded: bytes = field(init=False)
    lockhash: typing.LockHash = field(init=False)

    def __post_init__(self):
        packed = messages.Lock(buffer_for(messages.Lock))
        packed.amount = self.amount
        packed.expiration = self.expiration
        packed.secrethash = self.secrethash
        encoded = bytes(packed.data)

        self.encoded = encoded
        self.lockhash = typing.LockHash(sha3(encoded))

    def __hash__(self):
        return self.lockhash


@dataclass
class UnlockPartialProofState(State):
    lock: HashTimeLockState
    secret: typing.Secret


@dataclass
class UnlockProofState(State):
    merkle_proof: typing.List[typing.Keccak256]
    lock_encoded: bytes
    secret: typing.Secret


class TransactionState(Enum):
    SUCCESS = 'success'
    FAILURE = 'failure'
    UNKNOWN = 'unknown'


@dataclass
class TransactionExecutionStatus(State):
    started_block_number: typing.BlockNumber
    finished_block_number: typing.BlockNumber
    result: TransactionState = TransactionState.UNKNOWN


@dataclass
class MerkleTreeState(State):
    layers: typing.List[bytes]


@dataclass
class NettingChannelEndState(State):
    address: typing.Address
    contract_balance: typing.TokenAmount
    secrethashes_to_lockedlocks: SecretHashToLock = field(default_factory=dict)
    secrethashes_to_unlockedlocks: SecretHashToPartialUnlockProof = field(default_factory=dict)
    secrethashes_to_onchain_unlockedlocks: SecretHashToPartialUnlockProof = field(
        default_factory=dict,
    )
    merkletree: MerkleTreeState = field(default_factory=lambda: EMPTY_MERKLE_TREE)
    balance_proof: BalanceProofSignedState = None


@dataclass
class NettingChannelState(State):
    identifier: typing.ChannelID
    chain_id: typing.ChainID
    token_address: typing.Address
    payment_network_identifier: typing.PaymentNetworkID
    token_network_identifier: typing.Address
    reveal_timeout: typing.BlockNumber
    settle_timeout: typing.BlockNumber
    our_state: NettingChannelEndState
    partner_state: NettingChannelEndState
    open_transaction: TransactionExecutionStatus
    close_transaction: TransactionExecutionStatus
    settle_transaction: TransactionExecutionStatus
    deposit_transaction_queue: list = field(default_factory=list)
    our_unlock_transaction: TransactionExecutionStatus = None

    def __post_init__(self):
        if not isinstance(self.reveal_timeout, int) or self.reveal_timeout <= 0:
            raise ValueError('reveal_timeout must be a positive integer')

        if not isinstance(self.settle_timeout, int) or self.settle_timeout <= 0:
            raise ValueError('settle_timeout must be a positive integer')

        if not isinstance(self.open_transaction, TransactionExecutionStatus):
            raise ValueError('open_transaction must be a TransactionExecutionStatus instance')

        if not isinstance(self.identifier, typing.T_ChannelID):
            raise ValueError('channel identifier must be of type T_ChannelID')

        if self.reveal_timeout >= self.settle_timeout:
            raise ValueError('reveal_timeout must be smaller than settle_timeout')

        if self.open_transaction.result != TransactionState.SUCCESS:
            raise ValueError(
                'Cannot create a NettingChannelState with a non successfull open_transaction',
            )

        if self.identifier < 0 or self.identifier > UINT256_MAX:
            raise ValueError('channel identifier should be a uint256')

        valid_close_transaction = (
            self.close_transaction is None or
            isinstance(self.close_transaction, TransactionExecutionStatus)
        )
        if not valid_close_transaction:
            raise ValueError('close_transaction must be a TransactionExecutionStatus instance')

        valid_settle_transaction = (
            self.settle_transaction is None or
            isinstance(self.settle_transaction, TransactionExecutionStatus)
        )
        if not valid_settle_transaction:
            raise ValueError(
                'settle_transaction must be a TransactionExecutionStatus instance or None',
            )


@dataclass(order=True)
class TransactionChannelNewBalance(State):
    participant_address: typing.Address
    contract_balance: typing.TokenAmount
    deposit_block_number: typing.BlockNumber


EMPTY_MERKLE_ROOT = b'\x00' * 32
EMPTY_MERKLE_TREE = MerkleTreeState([
    [],                   # the leaves are empty
    [EMPTY_MERKLE_ROOT],  # the root is the constant 0
])
