# -*- coding: utf-8 -*-
import logging

from ethereum import slogging

from raiden.utils import random_secret
from raiden.routing import get_best_routes
from raiden.transfer import views
from raiden.transfer.state import BalanceProofSignedState
from raiden.transfer.state_change import (
    ReceiveProcessed,
    ReceiveTransferDirect,
    ReceiveUnlock,
)
from raiden.messages import (
    DirectTransfer,
    LockedTransfer,
    Message,
    Processed,
    RefundTransfer,
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.transfer.mediated_transfer.state import lockedtransfersigned_from_message
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def signedbalanceproof_from_message(message):
    return BalanceProofSignedState(
        message['nonce'],
        message['transferred_amount'],
        message['locksroot'],
        message['channel'],
        message['message_hash'],
        message['signature'],
        message['sender'],
    )


def handle_message_secretrequest(raiden: 'RaidenService', message: dict):
    secret_request = ReceiveSecretRequest(
        message['payment_identifier'],
        message['amount'],
        message['secrethash'],
        message['sender'],
    )
    raiden.handle_state_change(secret_request)


def handle_message_revealsecret(raiden: 'RaidenService', message: dict):
    state_change = ReceiveSecretReveal(
        message['secret'],
        message['sender'],
    )
    raiden.handle_state_change(state_change)


def handle_message_secret(raiden: 'RaidenService', message: dict):
    state_change = ReceiveUnlock(
        message['message_identifier'],
        message['secret'],
        signedbalanceproof_from_message(message),
    )
    raiden.handle_state_change(state_change)


def handle_message_refundtransfer(raiden: 'RaidenService', message: dict):
    registry_address = message['registry_address']
    from_transfer = lockedtransfersigned_from_message(message)
    node_state = views.state_from_raiden(raiden)

    routes = get_best_routes(
        node_state,
        registry_address,
        from_transfer.token,
        raiden.address,
        from_transfer.target,
        from_transfer.lock.amount,
        message['sender'],
    )

    role = views.get_transfer_role(
        node_state,
        from_transfer.lock.secrethash,
    )

    if role == 'initiator':
        secret = random_secret()
        state_change = ReceiveTransferRefundCancelRoute(
            registry_address,
            message['sender'],
            routes,
            from_transfer,
            secret,
        )
    else:
        state_change = ReceiveTransferRefund(
            message['message_identifier'],
            message['sender'],
            from_transfer,
        )

    raiden.handle_state_change(state_change)


def handle_message_directtransfer(raiden: 'RaidenService', message: dict):
    direct_transfer = ReceiveTransferDirect(
        message['registry_address'],
        message['token'],
        message['message_identifier'],
        message['payment_identifier'],
        signedbalanceproof_from_message(message),
    )

    raiden.handle_state_change(direct_transfer)


def handle_message_lockedtransfer(raiden: 'RaidenService', message: dict):
    if message.target == raiden.address:
        raiden.target_mediated_transfer(message)
    else:
        raiden.mediate_mediated_transfer(message)


def handle_message_processed(raiden: 'RaidenService', message: dict):
    processed = ReceiveProcessed(message.message_identifier)
    raiden.handle_state_change(processed)


def on_udp_message(raiden: 'RaidenService', message: Message):
    """ Return True if the message is known. """
    # pylint: disable=unidiomatic-typecheck
    if type(message) == SecretRequest:
        handle_message_secretrequest(raiden, message)
    elif type(message) == RevealSecret:
        handle_message_revealsecret(raiden, message)
    elif type(message) == Secret:
        handle_message_secret(raiden, message)
    elif type(message) == DirectTransfer:
        handle_message_directtransfer(raiden, message)
    elif type(message) == RefundTransfer:
        handle_message_refundtransfer(raiden, message)
    elif type(message) == LockedTransfer:
        handle_message_lockedtransfer(raiden, message)
    elif type(message) == Processed:
        handle_message_processed(raiden, message)
    elif log.isEnabledFor(logging.ERROR):
        log.error('Unknown message cmdid {}'.format(message.cmdid))
        return False

    # Inform the protocol that it's okay to send a Delivered message
    return True
