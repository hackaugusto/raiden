#!/usr/bin/env python

"""
This script is meant to be used as a template to step through a provided DB file
for debugging a specific issue.
It constructs the chain_state through the state_manager and uses the WAL
to replay all state changes through the state machines until all state changes are consumed.
The parameters (token_network_address and partner_address) will help filter out all
state changes until a channel is found with the provided token network address and partner.
The ignored state changes will still be applied, but they will just not be printed out.
"""
from contextlib import closing
from itertools import chain

import click
from eth_utils import encode_hex, is_checksum_address, to_canonical_address

from raiden.storage.serialization import JSONSerializer
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES, SerializedSQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.transfer import node, views
from raiden.transfer.architecture import Event, StateChange, StateManager
from raiden.utils.typing import (
    Address,
    Any,
    ChannelID,
    Dict,
    Iterable,
    Nonce,
    SecretHash,
    TokenNetworkAddress,
)


def state_change_contains_secrethash(obj: Any, secrethash: SecretHash) -> bool:
    return (hasattr(obj, "secrethash") and obj.secrethash == secrethash) or (
        hasattr(obj, "transfer")
        and (
            (hasattr(obj.transfer, "secrethash") and obj.transfer.secrethash == secrethash)
            or (hasattr(obj.transfer, "lock") and obj.transfer.lock.secrethash == secrethash)
        )
    )


def state_change_with_nonce(
    obj: Any, nonce: Nonce, channel_identifier: ChannelID, sender: Address
) -> bool:
    return (
        hasattr(obj, "balance_proof")
        and obj.balance_proof.nonce == nonce
        and obj.balance_proof.channel_identifier == channel_identifier
        and obj.balance_proof.sender == to_canonical_address(sender)
    )


def print_attributes(data: Dict) -> None:
    for key, value in data.items():
        if isinstance(value, bytes):
            value = encode_hex(value)

        click.echo("\t", nl=False)
        click.echo(click.style(key, fg="blue"), nl=False)
        click.echo(click.style("="), nl=False)
        click.echo(click.style(repr(value), fg="yellow"))


def print_state_change(state_change: StateChange) -> None:
    click.echo(click.style(f"> {state_change.__class__.__name__}", fg="red", bold=True))
    print_attributes(state_change.__dict__)


def print_events(events: Iterable[Event]) -> None:
    for event in events:
        click.echo(click.style(f"< {event.__class__.__name__}", fg="green", bold=True))
        print_attributes(event.__dict__)


def replay_wal(
    storage: SerializedSQLiteStorage,
    token_network_address: TokenNetworkAddress,
    partner_address: Address,
) -> None:
    all_state_changes = storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)

    state_manager = StateManager(state_transition=node.state_transition, current_state=None)
    wal = WriteAheadLog(state_manager, storage)

    for _, state_change in enumerate(all_state_changes):
        # Dispatching the state changes one-by-one to easy debugging
        _, events = wal.state_manager.dispatch([state_change])

        chain_state = wal.state_manager.current_state
        msg = "Chain state must never be cleared up."
        assert chain_state, msg

        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state,
            to_canonical_address(token_network_address),
            to_canonical_address(partner_address),
        )

        if not channel_state:
            continue

        ###
        # Customize this to filter things further somewhere around here.
        # An example would be to add `import pdb; pdb.set_trace()`
        # and inspect the state.
        ###

        print_state_change(state_change)
        print_events(chain.from_iterable(events))


@click.command(help=__doc__)
@click.argument("db-file", type=click.Path(exists=True))
@click.argument("token-network-address")
@click.argument("partner-address")
def main(db_file, token_network_address, partner_address):
    assert is_checksum_address(token_network_address), "token_network_address must be provided"
    assert is_checksum_address(partner_address), "partner_address must be provided"

    with closing(SerializedSQLiteStorage(db_file, JSONSerializer())) as storage:
        replay_wal(
            storage=storage,
            token_network_address=token_network_address,
            partner_address=partner_address,
        )


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
