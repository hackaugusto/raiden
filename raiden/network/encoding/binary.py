# -*- coding: utf-8 -*-
import struct

from raiden.utils import typing


VERSION1_MAGICNUMBER = b'\x96\xf7'

PROCESSED_ID = b'\x00\x00'
PING_ID = b'\x00\x01'
PONG_ID = b'\x00\x02'
SECRETREQUEST_ID = b'\x00\x03'
SECRET_ID = b'\x00\x04'
DIRECTTRANSFER_ID = b'\x00\x05'
LOCKEDTRANSFER_ID = b'\x00\x06'
REFUNDTRANSFER_ID = b'\x00\x07'
SECRETREVEAL_ID = b'\x00\x08'
DELIVERED_ID = b'\x00\x09'

UINT64 = '8s'
UINT256 = '32s'
ETHEREUM_ADDRESS = '20s'
HASHED_DATA = '32s'
SIGNATURE = '65s'

NONCE = UINT64
PAYMENT_IDENTIFIER = UINT64
MESSAGE_IDENTIFIER = UINT64
DELIVERED_MESSAGE_IDENTIFIER = UINT64
EXPIRATION = UINT64

REGISTRY_ADDRESS = ETHEREUM_ADDRESS
TOKEN = ETHEREUM_ADDRESS
RECIPIENT = ETHEREUM_ADDRESS
TARGET = ETHEREUM_ADDRESS
INITIATOR = ETHEREUM_ADDRESS
SENDER = ETHEREUM_ADDRESS
CHANNEL = ETHEREUM_ADDRESS

LOCKSROOT = HASHED_DATA
SECRETHASH = HASHED_DATA
SECRET = HASHED_DATA

TRANSFERRED_AMOUNT = UINT256
AMOUNT = UINT256
FEE = UINT256

PROCESSED_FMT = (
    VERSION1_MAGICNUMBER +
    PROCESSED_ID +
    SENDER +
    MESSAGE_IDENTIFIER +
    SIGNATURE
)

PROCESSED_NAMES = (
    'sender',
    'message_identifier',
    'signature',
)

PROCESSED_KEYS = set(PROCESSED_NAMES)

DELIVERED_FMT = (
    VERSION1_MAGICNUMBER +
    DELIVERED_ID +
    DELIVERED_MESSAGE_IDENTIFIER +
    SIGNATURE
)

DELIVERED_NAMES = (
    'delivered_message_identifier',
    'signature',
)

DELIVERED_KEYS = set(DELIVERED_NAMES)

PING_FMT = (
    VERSION1_MAGICNUMBER +
    PING_ID +
    NONCE +
    SIGNATURE
)

PING_NAMES = (
    'nonce',
    'signature',
)

PING_KEYS = set(PING_NAMES)

PONG_FMT = (
    VERSION1_MAGICNUMBER +
    PONG_ID +
    NONCE +
    SIGNATURE
)

PONG_NAMES = (
    'nonce',
    'signature',
)

PONG_KEYS = set(PONG_NAMES)

SECRETREQUEST_FMT = (
    VERSION1_MAGICNUMBER +
    SECRETREQUEST_ID +
    MESSAGE_IDENTIFIER +
    PAYMENT_IDENTIFIER +
    SECRETHASH +
    AMOUNT +
    SIGNATURE
)

SECRETREQUEST_NAMES = (
    'message_identifier',
    'payment_identifier',
    'secrethash',
    'amount',
    'signature',
)

SECRETREQUEST_KEYS = set(SECRETREQUEST_NAMES)

SECRET_FMT = (
    VERSION1_MAGICNUMBER +
    SECRET_ID +
    MESSAGE_IDENTIFIER +
    PAYMENT_IDENTIFIER +
    SECRET +
    NONCE +
    CHANNEL +
    TRANSFERRED_AMOUNT +
    LOCKSROOT +
    SIGNATURE
)

SECRET_NAMES = (
    'message_identifier',
    'payment_identifier',
    'secret',
    'nonce',
    'channel',
    'transferred_amount',
    'locksroot',
    'signature',
)

SECRET_KEYS = set(SECRET_NAMES)

SECRETREVEAL_FMT = (
    VERSION1_MAGICNUMBER +
    SECRETREVEAL_ID +
    MESSAGE_IDENTIFIER +
    SECRET +
    SIGNATURE
)

SECRETREVEAL_NAMES = (
    'message_identifier',
    'secret',
    'signature',
)

SECRETREVEAL_KEYS = set(SECRETREVEAL_NAMES)

DIRECTTRANSFER_FMT = (
    VERSION1_MAGICNUMBER +
    DIRECTTRANSFER_ID +
    NONCE +
    MESSAGE_IDENTIFIER +
    PAYMENT_IDENTIFIER +
    REGISTRY_ADDRESS +
    TOKEN +
    CHANNEL +
    RECIPIENT +
    TRANSFERRED_AMOUNT +
    LOCKSROOT +
    SIGNATURE
)

DIRECTTRANSFER_NAMES = (
    'nonce',
    'message_identifier',
    'payment_identifier',
    'registry_address',
    'token',
    'channel',
    'recipient',
    'transferred_amount',
    'locksroot',
    'signature',
)

DIRECTTRANSFER_KEYS = set(DIRECTTRANSFER_NAMES)

LOCKEDTRANSFER_FMT = (
    VERSION1_MAGICNUMBER +
    LOCKEDTRANSFER_ID +
    NONCE +
    MESSAGE_IDENTIFIER +
    PAYMENT_IDENTIFIER +
    EXPIRATION +
    REGISTRY_ADDRESS +
    TOKEN +
    CHANNEL +
    RECIPIENT +
    TARGET +
    INITIATOR +
    LOCKSROOT +
    SECRETHASH +
    TRANSFERRED_AMOUNT +
    AMOUNT +
    FEE +
    SIGNATURE
)

LOCKEDTRANSFER_NAMES = (
    'nonce',
    'message_identifier',
    'payment_identifier',
    'expiration',
    'registry_address',
    'token',
    'channel',
    'recipient',
    'target',
    'initiator',
    'locksroot',
    'secrethash',
    'transferred_amount',
    'amount',
    'fee',
    'signature',
)

LOCKEDTRANSFER_KEYS = set(LOCKEDTRANSFER_NAMES)

REFUNDTRANSFER_FMT = (
    VERSION1_MAGICNUMBER +
    REFUNDTRANSFER_ID +
    NONCE +
    MESSAGE_IDENTIFIER +
    PAYMENT_IDENTIFIER +
    EXPIRATION +
    REGISTRY_ADDRESS +
    TOKEN +
    CHANNEL +
    RECIPIENT +
    TARGET +
    INITIATOR +
    LOCKSROOT +
    SECRETHASH +
    TRANSFERRED_AMOUNT +
    AMOUNT +
    FEE +
    SIGNATURE
)

REFUNDTRANSFER_NAMES = (
    'nonce',
    'message_identifier',
    'payment_identifier',
    'expiration',
    'registry_address',
    'token',
    'channel',
    'recipient',
    'target',
    'initiator',
    'locksroot',
    'secrethash',
    'transferred_amount',
    'amount',
    'fee',
    'signature',
)

REFUNDTRANSFER_KEYS = set(REFUNDTRANSFER_NAMES)


ID_TO_FMT = {
    PROCESSED_ID: PROCESSED_FMT,
    PING_ID: PING_FMT,
    PONG_ID: PONG_FMT,
    SECRETREQUEST_ID: SECRETREQUEST_FMT,
    SECRET_ID: SECRET_FMT,
    SECRETREVEAL_ID: SECRETREVEAL_FMT,
    DIRECTTRANSFER_ID: DIRECTTRANSFER_FMT,
    LOCKEDTRANSFER_ID: LOCKEDTRANSFER_FMT,
    REFUNDTRANSFER_ID: REFUNDTRANSFER_FMT,
    DELIVERED_ID: DELIVERED_FMT,
}

ID_TO_NAMES = {
    PROCESSED_ID: PROCESSED_NAMES,
    PING_ID: PING_NAMES,
    PONG_ID: PONG_NAMES,
    SECRETREQUEST_ID: SECRETREQUEST_NAMES,
    SECRET_ID: SECRET_NAMES,
    SECRETREVEAL_ID: SECRETREVEAL_NAMES,
    DIRECTTRANSFER_ID: DIRECTTRANSFER_NAMES,
    LOCKEDTRANSFER_ID: LOCKEDTRANSFER_NAMES,
    REFUNDTRANSFER_ID: REFUNDTRANSFER_NAMES,
    DELIVERED_ID: DELIVERED_NAMES,
}

ID_TO_KEYS = {
    PROCESSED_ID: PROCESSED_KEYS,
    PING_ID: PING_KEYS,
    PONG_ID: PONG_KEYS,
    SECRETREQUEST_ID: SECRETREQUEST_KEYS,
    SECRET_ID: SECRET_KEYS,
    SECRETREVEAL_ID: SECRETREVEAL_KEYS,
    DIRECTTRANSFER_ID: DIRECTTRANSFER_KEYS,
    LOCKEDTRANSFER_ID: LOCKEDTRANSFER_KEYS,
    REFUNDTRANSFER_ID: REFUNDTRANSFER_KEYS,
    DELIVERED_ID: DELIVERED_KEYS,
}


def encode(id_: int, data: dict) -> bytes:
    keys = ID_TO_KEYS.get(id_)

    if keys is None:
        raise ValueError('Invalid id_')

    if not keys == data.keys():
        raise ValueError(
            'Invalid data. Either fields are missing or there are extra fields'
        )

    fmt = ID_TO_FMT[id_]
    names = ID_TO_NAMES[id_]
    data_ordered = (
        data[name] for name in names
    )

    encoded = struct.pack(fmt, *data_ordered)

    return encoded


def decode(data: bytes, offset: int = 0) -> typing.Optional[dict]:
    if data[:2] != VERSION1_MAGICNUMBER:
        return None

    id_ = data[2:4]
    fmt = ID_TO_FMT.get(id_)

    if fmt is None:
        return None

    try:
        data_unpacked = struct.unpack_from(fmt, data, offset)
    except struct.error:
        return None

    decoded = dict(zip(ID_TO_NAMES[id_], data_unpacked))
    decoded['message_type'] = id_

    return decoded
