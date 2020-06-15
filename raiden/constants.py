import math
from dataclasses import dataclass
from enum import Enum

from eth_utils import keccak, to_canonical_address

from raiden.utils.formatting import to_checksum_address, to_hex_address
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    BlockHash,
    BlockNumber,
    ChainID,
    List,
    Literal,
    Locksroot,
    RaidenDBVersion,
    RaidenProtocolVersion,
    Secret,
    SecretHash,
    Signature,
    TokenAddress,
    TokenAmount,
    TransactionHash,
    Tuple,
)

LATEST = "https://api.github.com/repos/raiden-network/raiden/releases/latest"
RELEASE_PAGE = "https://github.com/raiden-network/raiden/releases"
DOC_URL = "https://docs.raiden.network/raiden-api-1"
SECURITY_EXPRESSION = r"\[CRITICAL UPDATE.*?\]"

RAIDEN_DB_VERSION = RaidenDBVersion(26)
SQLITE_MIN_REQUIRED_VERSION = (3, 9, 0)
PROTOCOL_VERSION = RaidenProtocolVersion(1)

UINT256_MAX = 2 ** 256 - 1
UINT64_MAX = 2 ** 64 - 1

SECONDS_PER_DAY = 24 * 60 * 60

RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT = TokenAmount(int(0.075 * 10 ** 18))
RED_EYES_PER_TOKEN_NETWORK_LIMIT = TokenAmount(int(250 * 10 ** 18))

GENESIS_BLOCK_NUMBER = BlockNumber(0)

# Relevant forks:
# BYZANTIUM https://eips.ethereum.org/EIPS/eip-609
# CONSTANTINOPLE https://eips.ethereum.org/EIPS/eip-1013


class EthereumForks(Enum):
    BYZANTIUM = BlockNumber(4_370_000)
    CONSTANTINOPLE = BlockNumber(7_280_000)


class RopstenForks(Enum):
    BYZANTIUM = BlockNumber(1_700_000)
    CONSTANTINOPLE = BlockNumber(4_230_000)


class KovanForks(Enum):
    BYZANTIUM = BlockNumber(0)
    CONSTANTINOPLE = BlockNumber(4_230_000)


class RinkebyForks(Enum):
    BYZANTIUM = BlockNumber(0)
    CONSTANTINOPLE = BlockNumber(3_660_663)


class GoerliForks(Enum):
    BYZANTIUM = BlockNumber(0)
    CONSTANTINOPLE = BlockNumber(0)


class Networks(Enum):
    MAINNET = ChainID(1)
    ROPSTEN = ChainID(3)
    RINKEBY = ChainID(4)
    GOERLI = ChainID(5)
    KOVAN = ChainID(42)
    SMOKETEST = ChainID(627)


# Set at 64 since parity's default is 64 and Geth's default is 128
# TODO: Make this configurable. Since in parity this is also a configurable value
STATE_PRUNING_AFTER_BLOCKS = 64
STATE_PRUNING_SAFETY_MARGIN = 8
NO_STATE_QUERY_AFTER_BLOCKS = STATE_PRUNING_AFTER_BLOCKS - STATE_PRUNING_SAFETY_MARGIN

NULL_ADDRESS_BYTES = bytes(20)
NULL_ADDRESS_HEX = to_hex_address(Address(NULL_ADDRESS_BYTES))
NULL_ADDRESS_CHECKSUM = to_checksum_address(Address(NULL_ADDRESS_BYTES))

EMPTY_HASH = BlockHash(bytes(32))
EMPTY_TRANSACTION_HASH = TransactionHash(bytes(32))
EMPTY_BALANCE_HASH = BalanceHash(bytes(32))
EMPTY_MESSAGE_HASH = AdditionalHash(bytes(32))
EMPTY_SIGNATURE = Signature(bytes(65))
EMPTY_SECRET = Secret(bytes(32))
EMPTY_SECRETHASH = SecretHash(bytes(32))
EMPTY_SECRET_SHA256 = sha256_secrethash(EMPTY_SECRET)
LOCKSROOT_OF_NO_LOCKS = Locksroot(keccak(b""))
EMPTY_LOCKSROOT = Locksroot(bytes(32))
ZERO_TOKENS = TokenAmount(0)

ABSENT_SECRET = Secret(b"")

SECRET_LENGTH = 32
SECRETHASH_LENGTH = 32

RECEIPT_FAILURE_CODE = 0


class EthClient(Enum):
    GETH = "geth"
    PARITY = "parity"


SNAPSHOT_STATE_CHANGES_COUNT = 500

# An arbitrary limit for transaction size in Raiden, added in PR #1990
TRANSACTION_GAS_LIMIT_UPPER_BOUND = int(0.4 * 3_141_592)
TRANSACTION_INTRINSIC_GAS = 21_000

# Used to add a 30% security margin to gas estimations in case the calculations are off
GAS_FACTOR = 1.3

# The more pending transfers there are, the more computationally complex
# it becomes to unlock them. Lest an unlocking operation fails because
# not enough gas is available, we define a gas limit for unlock calls
# and limit the number of pending transfers per channel so it is not
# exceeded. The limit is inclusive.
UNLOCK_TX_GAS_LIMIT = TRANSACTION_GAS_LIMIT_UPPER_BOUND
MAXIMUM_PENDING_TRANSFERS = 160


class Environment(Enum):
    """Environment configurations that can be chosen on the command line."""

    PRODUCTION = "production"
    DEVELOPMENT = "development"


class RoutingMode(Enum):
    """Routing mode configuration that can be chosen on the command line"""

    PFS = "pfs"
    LOCAL = "local"
    PRIVATE = "private"


GAS_REQUIRED_PER_SECRET_IN_BATCH = math.ceil(UNLOCK_TX_GAS_LIMIT / MAXIMUM_PENDING_TRANSFERS)
GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL = 100_000

CHECK_RDN_MIN_DEPOSIT_INTERVAL = 5 * 60
CHECK_GAS_RESERVE_INTERVAL = 5 * 60
CHECK_VERSION_INTERVAL = 3 * 60 * 60
CHECK_NETWORK_ID_INTERVAL = 5 * 60

DEFAULT_HTTP_REQUEST_TIMEOUT = 10.0  # seconds

DISCOVERY_DEFAULT_ROOM = "discovery"
MONITORING_BROADCASTING_ROOM = "monitoring"
PATH_FINDING_BROADCASTING_ROOM = "path_finding"
MATRIX_AUTO_SELECT_SERVER = "auto"

# According to the smart contracts as of 07/08:
# https://github.com/raiden-network/raiden-contracts/blob/fff8646ebcf2c812f40891c2825e12ed03cc7628/raiden_contracts/contracts/TokenNetwork.sol#L213
# channel_identifier can never be 0. We make this a requirement in the client and use this fact
# to signify that a channel_identifier of `0` passed to the messages adds them to the
# global queue
EMPTY_ADDRESS = b"\0" * 20

BLOCK_ID_LATEST: Literal["latest"] = "latest"
BLOCK_ID_PENDING: Literal["pending"] = "pending"

# Thresholds for the ``eth.getLogs`` call. Used to automatically adjust the block batch size.
ETH_GET_LOGS_TIMEOUT = 10
ETH_GET_LOGS_THRESHOLD_FAST = ETH_GET_LOGS_TIMEOUT // 4
ETH_GET_LOGS_THRESHOLD_SLOW = ETH_GET_LOGS_TIMEOUT // 2


@dataclass
class VersionCompatibility:
    lowest_version_inclusive: Tuple[int, ...]
    # Using exclusive for highest value otherwise we would need to use multiple
    # `float("inf")`
    highest_version_exclusive: Tuple[int, ...]

    def __post_init__(self) -> None:
        if self.lowest_version_inclusive >= self.highest_version_exclusive:
            raise ValueError(
                "`lowest_version_inclusive` must be lower than `highest_version_exclusive`"
            )

    def support_check(self, current_version: Tuple[int, ...]) -> bool:
        """ Semantic version check. """

        return (
            current_version >= self.lowest_version_inclusive
            and current_version < self.highest_version_exclusive
        )

    def __str__(self) -> str:
        return f">={self.lowest_version_inclusive}, <{self.highest_version_exclusive}"


@dataclass
class EthCompatibility:
    supported_versions: List[VersionCompatibility]

    def __post_init__(self) -> None:
        # Make sure the versions are in increasing and do not overlap
        for lower, higher in zip(self.supported_versions, self.supported_versions[1:]):
            if not lower.highest_version_exclusive < higher.lowest_version_inclusive:
                raise ValueError("Versions must be in incremental order and must not overlap")

    def support_check(self, current_version: Tuple[int, ...]) -> bool:
        """ Semantic version check with support for blacklists.

        Blacklisting is supported by having multiple entries, e.g.:

            EthCompatibility([
                VersionCompatibility((1,15,1), (1,16)),
                VersionCompatibility((1,17), (2,))
            ])

        The code above blacklist the verion `1.16`.
        """
        return any(version.support_check(current_version) for version in self.supported_versions)


GETH_COMPATIBILTY = EthCompatibility(
    [VersionCompatibility(lowest_version_inclusive=(1, 9, 7), highest_version_exclusive=(2,))]
)
PARITY_COMPATIBILITY = EthCompatibility(
    [VersionCompatibility(lowest_version_inclusive=(1, 7, 6), highest_version_exclusive=(3,))]
)

WEB3_BLOCK_NOT_FOUND_RETRY_COUNT = 3

WETH_TOKEN_ADDRESS = TokenAddress(
    to_canonical_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
)
DAI_TOKEN_ADDRESS = TokenAddress(
    to_canonical_address("0x6B175474E89094C44Da98b954EedeAC495271d0F")
)

FLAT_MED_FEE_MIN = 0
PROPORTIONAL_MED_FEE_MIN = 0
# This needs to limit the total slope of the fee function < 1
# This is also the per-hop fee, so the actual value per-channel is X / (2 + X)
PROPORTIONAL_MED_FEE_MAX = 1_000_000
IMBALANCE_MED_FEE_MIN = 0
IMBALANCE_MED_FEE_MAX = 50_000
