# pylint: disable=too-many-arguments
import collections
import inspect
import itertools
import random
import string

from coincurve import PrivateKey

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.messages import Lock, LockedTransfer
from raiden.transfer import balance_proof, channel
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import (
    HashTimeLockState,
    LockedTransferSignedState,
    LockedTransferUnsignedState,
    MediationPairState,
    TransferDescriptionWithSecretState,
    lockedtransfersigned_from_message,
)
from raiden.transfer.merkle_tree import merkleroot
from raiden.transfer.state import (
    EMPTY_MERKLE_ROOT,
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    NettingChannelEndState,
    NettingChannelState,
    RouteState,
    TransactionExecutionStatus,
    message_identifier_from_prng,
)
from raiden.transfer.utils import hash_balance_data
from raiden.utils import privatekey_to_address, publickey_to_address, random_secret, sha3, typing
from raiden_libs.utils.signing import eth_sign

EMPTY = object()


def if_empty(value, default):
    return value if value is not EMPTY else default


def make_uint256() -> int:
    return random.randint(0, UINT256_MAX)


def make_channel_identifier() -> typing.ChannelID:
    return typing.ChannelID(make_uint256())


def make_uint64() -> int:
    return random.randint(0, UINT64_MAX)


def make_balance() -> typing.Balance:
    return typing.Balance(random.randint(0, UINT256_MAX))


def make_block_number() -> typing.BlockNumber:
    return typing.BlockNumber(random.randint(0, UINT256_MAX))


def make_chain_id() -> typing.ChainID:
    return typing.ChainID(random.randint(0, UINT64_MAX))


def make_message_identifier() -> typing.MessageID:
    return typing.MessageID(random.randint(0, UINT64_MAX))


def make_20bytes() -> bytes:
    return bytes(''.join(random.choice(string.printable) for _ in range(20)), encoding='utf-8')


def make_address() -> typing.Address:
    return typing.Address(make_20bytes())


def make_32bytes() -> bytes:
    return bytes(''.join(random.choice(string.printable) for _ in range(32)), encoding='utf-8')


def make_transaction_hash() -> typing.TransactionHash:
    return typing.TransactionHash(make_32bytes())


def make_privatekey_bin() -> bin:
    return make_32bytes()


def make_payment_network_identifier() -> typing.PaymentNetworkID:
    return typing.PaymentNetworkID(make_address())


def make_keccak_hash() -> typing.Keccak256:
    return typing.Keccak256(make_32bytes())


def make_secret(i: int = EMPTY) -> bytes:
    if i is not EMPTY:
        return format(i, '>032').encode()
    else:
        return make_32bytes()


def make_privatekey(privatekey_bin: bytes = EMPTY) -> PrivateKey:
    privatekey_bin = if_empty(privatekey_bin, make_privatekey_bin())
    return PrivateKey(privatekey_bin)


def make_privatekey_address(
        privatekey: PrivateKey = EMPTY,
) -> typing.Tuple[PrivateKey, typing.Address]:
    privatekey = if_empty(privatekey, make_privatekey(privatekey_bin=None))
    publickey = privatekey.public_key.format(compressed=False)
    address = publickey_to_address(publickey)
    return (privatekey, address)


def make_route_from_channel(channel_state: NettingChannelState = EMPTY) -> RouteState:
    channel_state = if_empty(channel_state, make_channel_state())
    return RouteState(channel_state.partner_state.address, channel_state.identifier)


def make_channel_endstate(
        address: typing.Address = EMPTY,
        balance: typing.Balance = EMPTY,
) -> NettingChannelEndState:
    address = if_empty(address, make_address())
    balance = if_empty(balance, 0)
    return NettingChannelEndState(address, balance)


def make_channel_state(
        our_balance: typing.Balance = EMPTY,
        partner_balance: typing.Balance = EMPTY,
        our_address: typing.Address = EMPTY,
        partner_address: typing.Address = EMPTY,
        token_address: typing.TokenAddress = EMPTY,
        payment_network_identifier: typing.PaymentNetworkID = EMPTY,
        token_network_identifier: typing.TokenNetworkID = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        reveal_timeout: typing.BlockTimeout = EMPTY,
        settle_timeout: int = EMPTY,
) -> NettingChannelState:

    our_balance = if_empty(our_balance, 0)
    partner_balance = if_empty(partner_balance, 0)
    our_address = if_empty(our_address, make_address())
    partner_address = if_empty(partner_address, make_address())
    token_address = if_empty(token_address, make_address())
    payment_network_identifier = if_empty(
        payment_network_identifier,
        make_payment_network_identifier(),
    )
    token_network_identifier = if_empty(token_network_identifier, make_address())
    channel_identifier = if_empty(channel_identifier, make_channel_identifier())
    reveal_timeout = if_empty(reveal_timeout, UNIT_REVEAL_TIMEOUT)
    settle_timeout = if_empty(settle_timeout, UNIT_SETTLE_TIMEOUT)

    opened_block_number = 10
    close_transaction: TransactionExecutionStatus = None
    settle_transaction: TransactionExecutionStatus = None
    our_state = make_channel_endstate(
        address=our_address,
        balance=our_balance,
    )
    partner_state = make_channel_endstate(
        address=partner_address,
        balance=partner_balance,
    )
    open_transaction = TransactionExecutionStatus(
        started_block_number=None,
        finished_block_number=opened_block_number,
        result=TransactionExecutionStatus.SUCCESS,
    )

    return NettingChannelState(
        identifier=channel_identifier,
        chain_id=UNIT_CHAIN_ID,
        token_address=token_address,
        payment_network_identifier=payment_network_identifier,
        token_network_identifier=token_network_identifier,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=open_transaction,
        close_transaction=close_transaction,
        settle_transaction=settle_transaction,
    )


def make_transfer_description(
        payment_network_identifier: typing.PaymentNetworkID = EMPTY,
        payment_identifier: typing.PaymentID = EMPTY,
        amount: typing.TokenAmount = EMPTY,
        token_network: typing.TokenNetworkID = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        secret: typing.Secret = EMPTY,
) -> TransferDescriptionWithSecretState:
    payment_network_identifier = if_empty(
        payment_network_identifier,
        UNIT_PAYMENT_NETWORK_IDENTIFIER,
    )
    payment_identifier = if_empty(payment_identifier, UNIT_TRANSFER_IDENTIFIER)
    amount = if_empty(amount, UNIT_TRANSFER_AMOUNT)
    token_network = if_empty(token_network, UNIT_TOKEN_NETWORK_ADDRESS)
    initiator = if_empty(initiator, UNIT_TRANSFER_INITIATOR)
    target = if_empty(target, UNIT_TRANSFER_TARGET)
    secret = if_empty(secret, random_secret())

    return TransferDescriptionWithSecretState(
        payment_network_identifier=payment_network_identifier,
        payment_identifier=payment_identifier,
        amount=amount,
        token_network_identifier=token_network,
        initiator=initiator,
        target=target,
        secret=secret,
    )


def make_transfer(
        amount: typing.TokenAmount = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        expiration: typing.BlockExpiration = EMPTY,
        secret: typing.Secret = EMPTY,
        identifier: typing.PaymentID = EMPTY,
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        token_network_identifier: typing.TokenNetworkID = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        locksroot: typing.Locksroot = EMPTY,
        token: typing.TargetAddress = EMPTY,
):
    amount = if_empty(amount, UNIT_TRANSFER_AMOUNT)
    initiator = if_empty(initiator, make_address())
    target = if_empty(target, make_address())
    expiration = if_empty(expiration, UNIT_REVEAL_TIMEOUT)
    secret = if_empty(secret, make_secret())
    identifier = if_empty(identifier, 1)
    nonce = if_empty(nonce, 1)
    transferred_amount = if_empty(transferred_amount, 0)
    token_network_identifier = if_empty(token_network_identifier, UNIT_TOKEN_NETWORK_ADDRESS)
    channel_identifier = if_empty(channel_identifier, UNIT_CHANNEL_ID)
    token = if_empty(token, UNIT_TOKEN_ADDRESS)

    secrethash = sha3(secret)
    lock = HashTimeLockState(
        amount=amount,
        expiration=expiration,
        secrethash=secrethash,
    )

    if locksroot is EMPTY:
        locksroot = lock.lockhash
        locked_amount = amount
    else:
        assert locked_amount

    unsigned_balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        token_network_identifier=token_network_identifier,
        channel_identifier=channel_identifier,
        chain_id=UNIT_CHAIN_ID,
    )

    return LockedTransferUnsignedState(
        payment_identifier=identifier,
        token=token,
        balance_proof=unsigned_balance_proof,
        lock=lock,
        initiator=initiator,
        target=target,
    )


def make_signed_transfer(
        amount: typing.TokenAmount = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        expiration: typing.BlockExpiration = EMPTY,
        secret: typing.Secret = EMPTY,
        payment_identifier: typing.PaymentID = EMPTY,
        message_identifier: typing.MessageID = EMPTY,
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        locksroot: typing.Locksroot = EMPTY,
        recipient: typing.Address = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        token_network_address: typing.TokenNetworkID = EMPTY,
        token: typing.TargetAddress = EMPTY,
        pkey: PrivateKey = EMPTY,
        sender: typing.Address = EMPTY,
) -> LockedTransferSignedState:

    amount = if_empty(amount, UNIT_TRANSFER_AMOUNT)
    initiator = if_empty(initiator, make_address())
    target = if_empty(target, make_address())
    expiration = if_empty(expiration, UNIT_REVEAL_TIMEOUT)
    secret = if_empty(secret, make_secret())
    payment_identifier = if_empty(payment_identifier, 1)
    message_identifier = if_empty(message_identifier, make_message_identifier())
    nonce = if_empty(nonce, 1)
    transferred_amount = if_empty(transferred_amount, 0)
    locked_amount = if_empty(locked_amount, amount)
    locksroot = if_empty(locksroot, EMPTY_MERKLE_ROOT)
    recipient = if_empty(recipient, UNIT_TRANSFER_TARGET)
    channel_identifier = if_empty(channel_identifier, UNIT_CHANNEL_ID)
    token_network_address = if_empty(token_network_address, UNIT_TOKEN_NETWORK_ADDRESS)
    token = if_empty(token, UNIT_TOKEN_ADDRESS)
    pkey = if_empty(pkey, UNIT_TRANSFER_PKEY)
    sender = if_empty(sender, UNIT_TRANSFER_SENDER)

    assert locked_amount >= amount

    secrethash = sha3(secret)
    lock = Lock(
        amount=amount,
        expiration=expiration,
        secrethash=secrethash,
    )

    if locksroot == EMPTY_MERKLE_ROOT:
        locksroot = sha3(lock.as_bytes)

    transfer = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=token_network_address,
        token=token,
        channel_identifier=channel_identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=recipient,
        locksroot=locksroot,
        lock=lock,
        target=target,
        initiator=initiator,
    )
    transfer.sign(pkey)
    assert transfer.sender == sender

    return lockedtransfersigned_from_message(transfer)


def make_signed_balance_proof(
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        token_network_address: typing.TokenNetworkID = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        locksroot: typing.Locksroot = EMPTY,
        extra_hash: typing.Keccak256 = EMPTY,
        private_key: PrivateKey = EMPTY,
        sender_address: typing.Address = EMPTY,
) -> BalanceProofSignedState:

    nonce = if_empty(nonce, make_uint256())
    transferred_amount = if_empty(transferred_amount, make_uint256())
    locked_amount = if_empty(locked_amount, make_uint256())
    token_network_address = if_empty(token_network_address, make_address())
    channel_identifier = if_empty(channel_identifier, make_uint256())
    locksroot = if_empty(locksroot, make_32bytes())
    extra_hash = if_empty(extra_hash, make_keccak_hash())
    private_key = if_empty(private_key, make_privatekey())
    sender_address = if_empty(sender_address, make_address())

    balance_hash = hash_balance_data(
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
    )
    data_to_sign = balance_proof.pack_balance_proof(
        nonce=nonce,
        balance_hash=balance_hash,
        additional_hash=extra_hash,
        channel_identifier=channel_identifier,
        token_network_identifier=token_network_address,
        chain_id=UNIT_CHAIN_ID,
    )

    signature = eth_sign(privkey=private_key, data=data_to_sign)

    return BalanceProofSignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        token_network_identifier=token_network_address,
        channel_identifier=channel_identifier,
        message_hash=extra_hash,
        signature=signature,
        sender=sender_address,
        chain_id=UNIT_CHAIN_ID,
    )


def make_signed_transfer_for(
        channel_state: NettingChannelState = EMPTY,
        amount: typing.TokenAmount = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        expiration: typing.BlockExpiration = EMPTY,
        secret: typing.Secret = EMPTY,
        identifier: typing.PaymentID = EMPTY,
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        pkey: PrivateKey = EMPTY,
        sender: typing.Address = EMPTY,
        compute_locksroot: typing.Locksroot = EMPTY,
        allow_invalid: bool = EMPTY,
):

    channel_state = if_empty(channel_state, make_channel_state())
    amount = if_empty(amount, 0)
    initiator = if_empty(initiator, make_address())
    target = if_empty(target, make_address())
    expiration = if_empty(expiration, UNIT_REVEAL_TIMEOUT)
    secret = if_empty(secret, make_secret())
    identifier = if_empty(identifier, 1)
    nonce = if_empty(nonce, 1)
    transferred_amount = if_empty(transferred_amount, 0)
    pkey = if_empty(pkey, UNIT_TRANSFER_PKEY)
    sender = if_empty(sender, UNIT_TRANSFER_SENDER)
    compute_locksroot = if_empty(compute_locksroot, False)
    allow_invalid = if_empty(allow_invalid, False)

    if not allow_invalid:
        msg = 'expiration must be lower than settle_timeout'
        assert expiration < channel_state.settle_timeout, msg
        msg = 'expiration must be larger than reveal_timeout'
        assert expiration > channel_state.reveal_timeout, msg

    pubkey = pkey.public_key.format(compressed=False)
    assert publickey_to_address(pubkey) == sender

    assert sender in (channel_state.our_state.address, channel_state.partner_state.address)
    if sender == channel_state.our_state.address:
        recipient = channel_state.partner_state.address
    else:
        recipient = channel_state.our_state.address

    channel_identifier = channel_state.identifier
    token_address = channel_state.token_address

    if compute_locksroot:
        locksroot = merkleroot(channel.compute_merkletree_with(
            channel_state.partner_state.merkletree,
            sha3(Lock(amount, expiration, sha3(secret)).as_bytes),
        ))
    else:
        locksroot = EMPTY_MERKLE_ROOT

    mediated_transfer = make_signed_transfer(
        amount=amount,
        initiator=initiator,
        target=target,
        expiration=expiration,
        secret=secret,
        payment_identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
        locksroot=locksroot,
        locked_amount=locked_amount,
        recipient=recipient,
        channel_identifier=channel_identifier,
        token_network_address=channel_state.token_network_identifier,
        token=token_address,
        pkey=pkey,
        sender=sender,
    )

    # Do *not* register the transfer here
    if not allow_invalid:
        is_valid, msg, _ = channel.is_valid_lockedtransfer(
            mediated_transfer,
            channel_state,
            channel_state.partner_state,
            channel_state.our_state,
        )
        assert is_valid, msg

    return mediated_transfer


def make_transfers_pair(privatekeys, amount, block_number):
    transfers_pair = list()
    channel_map = dict()
    pseudo_random_generator = random.Random()

    addresses = list()
    for pkey in privatekeys:
        pubkey = pkey.public_key.format(compressed=False)
        address = publickey_to_address(pubkey)
        addresses.append(address)

    key_address = list(zip(privatekeys, addresses))

    deposit_amount = amount * 5
    channels_state = {
        address: make_channel(
            our_address=HOP1,
            our_balance=deposit_amount,
            partner_balance=deposit_amount,
            partner_address=address,
            token_address=UNIT_TOKEN_ADDRESS,
            token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
        )
        for address in addresses
    }

    lock_expiration = block_number + UNIT_REVEAL_TIMEOUT * 2
    for (payer_key, payer_address), payee_address in zip(key_address[:-1], addresses[1:]):
        pay_channel = channels_state[payee_address]
        receive_channel = channels_state[payer_address]

        received_transfer = make_signed_transfer(
            amount=amount,
            initiator=UNIT_TRANSFER_INITIATOR,
            target=UNIT_TRANSFER_TARGET,
            expiration=lock_expiration,
            secret=UNIT_SECRET,
            payment_identifier=UNIT_TRANSFER_IDENTIFIER,
            channel_identifier=receive_channel.identifier,
            pkey=payer_key,
            sender=payer_address,
        )

        is_valid, _, msg = channel.handle_receive_lockedtransfer(
            receive_channel,
            received_transfer,
        )
        assert is_valid, msg

        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        lockedtransfer_event = channel.send_lockedtransfer(
            channel_state=pay_channel,
            initiator=UNIT_TRANSFER_INITIATOR,
            target=UNIT_TRANSFER_TARGET,
            amount=amount,
            message_identifier=message_identifier,
            payment_identifier=UNIT_TRANSFER_IDENTIFIER,
            expiration=lock_expiration,
            secrethash=UNIT_SECRETHASH,
        )
        assert lockedtransfer_event
        lock_timeout = lock_expiration - block_number
        assert mediator.is_channel_usable(
            candidate_channel_state=pay_channel,
            transfer_amount=amount,
            lock_timeout=lock_timeout,
        )
        sent_transfer = lockedtransfer_event.transfer

        pair = MediationPairState(
            received_transfer,
            lockedtransfer_event.recipient,
            sent_transfer,
        )
        transfers_pair.append(pair)

        channel_map[receive_channel.identifier] = receive_channel
        channel_map[pay_channel.identifier] = pay_channel

        assert channel.is_lock_locked(receive_channel.partner_state, UNIT_SECRETHASH)
        assert channel.is_lock_locked(pay_channel.our_state, UNIT_SECRETHASH)

    return channel_map, transfers_pair


# Goals:
# - Make it easier to write tests:
#   - Reduce the number of variables a test needs to manage by introducing hidden state
#   - Automate duplicated tasks:
#     - Creating topologies
#   - Easy to control the messages sent/received:
#     - Simulate concurrency by interleaving state changes for differents transfers
#     - Simulate networks problems by delaying/replaying/dropping state changes
#     - Simulate attacks by producing invalid state changes (with or without valid signatures)
#   - Easy to test multiple nodes:
#     - To test both ends of a channel and simulate a network
#   - Easy to assert on valid states:
#     - Needs to take into account difference of views of both nodes:
#       - assertions that are valid globally
#       - assertions that are valid locally
#       - assertions that are valid after a given state change


def get_defaults(argspec):
    """ Returns a dictionary with the default arguments of a function.

    This handles defaults for keyword only and normal arguments.
    """
    # This assumes the language forbids duplicate names for function arguments
    if argspec.kwonlydefaults is not None:
        args = dict(argspec.kwonlydefaults)
    else:
        args = dict()

    if argspec.defaults is not None:
        positional_with_defaults = argspec.args[-len(argspec.defaults):]
        args.update(zip(positional_with_defaults, argspec.defaults))

    return args


def make_chainmap(defaults):
    """ Returns a ChainMap create out of defaults. """
    if defaults is not None and not isinstance(defaults, collections.ChainMap):
        variables = collections.ChainMap(defaults)
    elif defaults is None:
        variables = collections.ChainMap()
    else:
        variables = defaults

    return variables


def _rank_annotations(annotations, cache: dict) -> None:
    """ Rank annotations by simplicity.

    This algorithm is intentionally recursive, this will raise RecursionError
    if there are reference cycles which are not supported.
    """
    for func in annotations:
        rank = cache.get(func, EMPTY)

        if rank is not EMPTY:
            continue

        try:
            argspec = inspect.getfullargspec(func)
        except TypeError:
            # Assume it's a builtin without arguments. If it's a c function
            # with more then one argument, for this to work it needs to
            # wrapped with a python function that exposes the argspec
            cache[func] = 1
        else:
            rank = 0
            for arg in argspec.args + argspec.kwonlyargs:
                subfunc = argspec.annotations.get(arg, EMPTY)
                if subfunc is not EMPTY:
                    _rank_annotations([subfunc], cache)
                    rank += cache[subfunc]
                else:
                    rank += 1

            cache[func] = rank


def order_by_simplicity(  # pylint: disable=dangerous-default-value
        annotations,
        cache=dict(),  # NOQA
):
    """ Return the annotations ordered by simplicity. """
    _rank_annotations(annotations, cache)

    classification = dict()
    for func in annotations:
        rank = cache.get(func, EMPTY)
        classification.setdefault(rank, list()).append(func)

    ordered = itertools.chain.from_iterable(
        items
        for _, items in sorted(classification.items())
    )
    return list(ordered)


class Forestry:
    """ A factory for objects with a nursery to share state.

    Note:
        This factory will only work with classes which are structured in trees,
        if there are reference cycles it can not be used.
    """

    def __init__(self, defaults: dict = None, factories: dict = None):
        # name alone is not a good enough key to select values, consider this
        # name collision:
        #
        # def f(id: A, b: g): pass
        # def g(id: B)
        #
        # If the arguments are define only by name, then `g` will be called
        # with an invalid type. Additionally, it's not possible to do
        # isinstance checks because either A or B could be a typing type.
        self.nursery = make_chainmap(defaults)
        self.factories = factories or dict()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def __getitem__(self, key):
        return self.nursery[key]

    def __setitem__(self, key, value):
        self.nursery[key] = value

    def __delitem__(self, key):
        del self.nursery[key]

    def overwrite(self, **overwrites):
        return Forestry(self.nursery.new_child(overwrites))

    def create(self, what):
        """ Create an instance of `what`.

        If there is a factory associated with `what`, this factory function is
        called, and the arguments passed to it are the ones in this nursery.

        Values currently in the nursery always have priority. If there is no
        value for the given argument but `func` has a default argument, that is
        used instead of creating a new object. Otherwise a new object is
        created.

        Object creation follows a simple rule: types are ranked by simplicity
        and the simplest are created first. The simplicity is a partial order
        of types, determined by the total number of dependencies required to
        createa an instance of it. An object without any dependencies is the
        simplest, an object with one argument the next, and so on. Objects with
        the same rank will be created in order of declaration.

        The creation order rule is used to make it easier to share state of
        parent objects with child objects.

        Note:
            varargs is ignored, it cannot be called by keyword

        Raises:
            TypeError: if costructing the argument for func failed.
            RecursionError: if there are reference cycles.
        """
        factory = self.factories.get(what, what)

        if not callable(factory):
            raise ValueError(
                f'Cant create an instance of {repr(what)} because it is not '
                f'callable and there is no factory associated to it.',
            )

        try:
            # If there are missing arguments, create a new nursery. This allow
            # random factories to create instantiate different objects which
            # share a subset of the state.
            extra_args = self.missing_callargs_for(factory)
            if extra_args:
                return self.overwrite(**extra_args).create(what)

            call_args = self.callargs_for(factory)
            instance = factory(**call_args)
        except TypeError:
            # builtins raise type error on inspect, assume no arguments
            instance = factory()

        return instance

    def missing_callargs_for(self, func):
        """ Return a dictionary with arguments which missing from the current
        nursery to call func.

        This will create objects following the simplicity rule *without*
        updating the current nursery.

        The /simplicity rule/ is applied to the annotation of *func* and /not/
        the corresponding factory, if any. It also ignores if there are any
        dependencies already in the nursery.

        The nursery is not updated because otherwise /every/ subsequent object
        would always be equal, where the intended behavior is just for them to
        share some of the state.

        Note:
            Not all names to will necessarily have a value, meaning the
            function call may fail. This is intentional to allow methods to be
            called, where the variable `self` must not be assigned. This will
            intentionally not work with unbound functions.

        Raises:
            TypeError: if func cannot be inspected.
            RecursionError: if there are reference cycles.
        """
        argspec = inspect.getfullargspec(func)
        callargs = get_defaults(argspec)
        argument_names = argspec.args + argspec.kwonlyargs

        missing_annotations = list()
        for name in argument_names:
            annotation = argspec.annotations.get(name, EMPTY)

            # Only creates values for missing values which have a type
            # annotation. This handles methods, which have a default value for
            # `self` injected by language runtime.
            add_missing = (
                name not in self.nursery and
                name not in callargs and
                annotation is not EMPTY and
                annotation not in self.nursery
            )

            if add_missing:
                missing_annotations.append(annotation)

        missing_callargs = dict()
        for missing in order_by_simplicity(missing_annotations):
            missing_callargs[missing] = self.create(missing)

        return missing_callargs

    def callargs_for(self, func):
        """ Return a dictionary with arguments from the nursey which are
        necessary to call func.

        Note:
            Not all names to will necessarily have a value, meaning the
            function call may fail. This is intentional to allow methods to be
            called, where the variable `self` must not be assigned. This will
            intentionally not work with unbound functions.
        """
        argspec = inspect.getfullargspec(func)
        callargs = get_defaults(argspec)
        argument_names = argspec.args + argspec.kwonlyargs

        for name in argument_names:
            annotation = argspec.annotations.get(name)
            value_by_type = self.nursery.get(annotation, EMPTY)
            value_by_name = self.nursery.get(name, EMPTY)

            # value by name takes priority because it makes possible to provide
            # different values for the same type. Consider the function:
            #
            # def f(a: int, b: int): pass
            #
            # If the value by type had priority then it's not possible to
            # provide differents values for a and b
            if value_by_name is not EMPTY:
                callargs[name] = value_by_name
            elif value_by_type is not EMPTY:
                callargs[name] = value_by_type

        return callargs


# ALIASES
make_channel = make_channel_state
route_from_channel = make_route_from_channel
make_endstate = make_channel_endstate
make_privkey_address = make_privatekey_address

# CONSTANTS
# In this module constans are in the bottom because we need some of the
# factories.
# Prefixing with UNIT_ to differ from the default globals.
UNIT_SETTLE_TIMEOUT = 50
UNIT_REVEAL_TIMEOUT = 5
UNIT_TRANSFER_AMOUNT = 10
UNIT_SECRET = b'secretsecretsecretsecretsecretse'
UNIT_SECRETHASH = sha3(UNIT_SECRET)
UNIT_REGISTRY_IDENTIFIER = b'registryregistryregi'
UNIT_TOKEN_ADDRESS = b'tokentokentokentoken'
UNIT_TOKEN_NETWORK_ADDRESS = b'networknetworknetwor'
UNIT_CHANNEL_ID = 1338
UNIT_PAYMENT_NETWORK_IDENTIFIER = b'paymentnetworkidentifier'
UNIT_TRANSFER_IDENTIFIER = 37
UNIT_TRANSFER_INITIATOR = b'initiatorinitiatorin'
UNIT_TRANSFER_TARGET = b'targettargettargetta'
UNIT_TRANSFER_PKEY_BIN = sha3(b'transfer pkey')
UNIT_TRANSFER_PKEY = PrivateKey(UNIT_TRANSFER_PKEY_BIN)
UNIT_TRANSFER_SENDER = privatekey_to_address(sha3(b'transfer pkey'))
HOP1_KEY = PrivateKey(b'11111111111111111111111111111111')
HOP2_KEY = PrivateKey(b'22222222222222222222222222222222')
HOP3_KEY = PrivateKey(b'33333333333333333333333333333333')
HOP4_KEY = PrivateKey(b'44444444444444444444444444444444')
HOP5_KEY = PrivateKey(b'55555555555555555555555555555555')
HOP6_KEY = PrivateKey(b'66666666666666666666666666666666')
HOP1 = privatekey_to_address(b'11111111111111111111111111111111')
HOP2 = privatekey_to_address(b'22222222222222222222222222222222')
HOP3 = privatekey_to_address(b'33333333333333333333333333333333')
HOP4 = privatekey_to_address(b'44444444444444444444444444444444')
HOP5 = privatekey_to_address(b'55555555555555555555555555555555')
HOP6 = privatekey_to_address(b'66666666666666666666666666666666')
UNIT_CHAIN_ID = 337
ADDR = b'addraddraddraddraddr'
UNIT_TRANSFER_DESCRIPTION = make_transfer_description(secret=UNIT_SECRET)


RANDOM_FACTORIES = {
    typing.Address: make_address,
    typing.Balance: make_balance,
    typing.BlockNumber: make_block_number,
    typing.BlockTimeout: make_block_number,
    typing.ChainID: make_chain_id,
    typing.ChannelID: make_channel_identifier,
    typing.PaymentNetworkID: make_payment_network_identifier,
    typing.TokenNetworkID: make_payment_network_identifier,
    NettingChannelState: make_channel_state,
}
