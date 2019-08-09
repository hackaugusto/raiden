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
from pathlib import Path

import click
from eth_utils import decode_hex, encode_hex, to_canonical_address

from raiden.storage.serialization import JSONSerializer
from raiden.storage.sqlite import (
    HIGH_STATECHANGE_ULID,
    RANGE_ALL_STATE_CHANGES,
    SerializedSQLiteStorage,
    StateChangeID,
)
from raiden.storage.ulid import ULID
from raiden.storage.wal import WriteAheadLog, restore_to_state_change
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


def restore_by_state_change(
    storage: SerializedSQLiteStorage, state_change_identifier: StateChangeID
) -> None:
    wal = restore_to_state_change(
        transition_function=node.state_transition,
        storage=storage,
        state_change_identifier=state_change_identifier,
    )

    if wal:
        breakpoint()
    else:
        print(f"Couldn't restore to {state_change_identifier}")


def hexulid(hexulid: str) -> ULID:
    return ULID(decode_hex(hexulid))


def storage_from_path(db_file: str) -> Path:
    file = Path(db_file)
    assert file.exists
    return file


def main():
    import argparse

    main_parser = argparse.ArgumentParser()
    main_parser.add_argument("database_path", type=storage_from_path)
    commands = main_parser.add_subparsers(dest="command", required=True)

    replay_parser = commands.add_parser("replay")
    replay_group = replay_parser.add_mutually_exclusive_group()
    replay_group.add_argument("--state-change-ulid", type=hexulid, default=HIGH_STATECHANGE_ULID)

    args = main_parser.parse_args()

    with closing(SerializedSQLiteStorage(args.database_path, JSONSerializer())) as storage:
        if args.command == "replay":
            if "state_change_ulid" in args:
                restore_by_state_change(storage, args.state_change_ulid)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
