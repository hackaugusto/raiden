from copy import deepcopy
from dataclasses import dataclass

import gevent.lock
import structlog

from raiden.storage.serialization import DictSerializer
from raiden.storage.sqlite import (
    LOW_STATECHANGE_ULID,
    Range,
    SerializedSQLiteStorage,
    StateChangeID,
)
from raiden.transfer.architecture import Event, State, StateChange, StateManager
from raiden.utils.formatting import to_checksum_address
from raiden.utils.logging import redact_secret
from raiden.utils.typing import (
    Address,
    Callable,
    Generic,
    List,
    Optional,
    RaidenDBVersion,
    Tuple,
    TypeVar,
)

log = structlog.get_logger(__name__)


def restore_state(
    transition_function: Callable,
    storage: SerializedSQLiteStorage,
    state_change_identifier: StateChangeID,
    node_address: Address,
    initial_state: State,
) -> Optional[State]:
    """Restores the state manager from the database, if any, otherwise returns `None`."""
    snapshot = storage.get_snapshot_before_state_change(
        state_change_identifier=state_change_identifier
    )

    if snapshot is not None:
        log.debug(
            "Snapshot found",
            from_state_change_id=snapshot.state_change_identifier,
            to_state_change_id=state_change_identifier,
            node=to_checksum_address(node_address),
        )
        from_identifier = snapshot.state_change_identifier
        chain_state = snapshot.data
    else:
        log.debug(
            "No snapshot found",
            to_state_change_id=state_change_identifier,
            node=to_checksum_address(node_address),
        )
        from_identifier = LOW_STATECHANGE_ULID
        chain_state = initial_state

    unapplied_state_changes = storage.get_statechanges_by_range(
        Range(from_identifier, state_change_identifier)
    )

    # The database is clean, return None to inform the caller.
    if not snapshot and not unapplied_state_changes:
        return None

    log.debug(
        "Replaying state changes",
        replayed_state_changes=[
            redact_secret(DictSerializer.serialize(state_change))
            for state_change in unapplied_state_changes
        ],
        node=to_checksum_address(node_address),
    )

    state_manager = StateManager(transition_function, chain_state, unapplied_state_changes)

    return state_manager.current_state


ST = TypeVar("ST", bound=State)


@dataclass(frozen=True)
class SavedState(Generic[ST]):
    """Saves the state and the id of the state change that produced it.

    This datastructure keeps the state and the state_change_id synchronized.
    Having these values available is useful for debugging.
    """

    state_change_id: StateChangeID
    state: ST


class WriteAheadLog(Generic[ST]):
    saved_state: SavedState[ST]

    def __init__(self, state_manager: StateManager[ST], storage: SerializedSQLiteStorage) -> None:
        self._state_manager = state_manager
        self.storage = storage

        # The state changes must be applied in the same order as they are saved
        # to the WAL. Because writing to the database context switches, and the
        # scheduling is undetermined, a lock is necessary to protect the
        # execution order.
        self._lock = gevent.lock.Semaphore()

    def log_and_dispatch(self, state_changes: List[StateChange]) -> Tuple[ST, List[Event]]:
        """ Log and apply a state change.

        This function will first write the state change to the write-ahead-log,
        in case of a node crash the state change can be recovered and replayed
        to restore the node state.

        Events produced by applying state change are also saved.
        """

        with self._lock:
            all_state_change_ids = self.storage.write_state_changes(state_changes)

            latest_state, all_events = self._state_manager.dispatch(state_changes)
            latest_state_change_id = all_state_change_ids[-1]

            # The update must be done with a single operation, to make sure
            # that readers will have a consistent view of it.
            self.saved_state = SavedState(latest_state_change_id, latest_state)

            event_data = list()
            flattened_events = list()
            for state_change_id, events in zip(all_state_change_ids, all_events):
                flattened_events.extend(events)
                for event in events:
                    event_data.append((state_change_id, event))

            self.storage.write_events(event_data)

        return latest_state, flattened_events

    def snapshot(self) -> None:
        """ Snapshot the application state.

        Snapshots are used to restore the application state, either after a
        restart or a crash.
        """
        with self._lock:
            current_state = self._state_manager.current_state
            state_change_id = self.saved_state.state_change_id

            # otherwise no state change was dispatched
            if state_change_id and current_state is not None:
                self.storage.write_state_snapshot(current_state, state_change_id)

    def get_current_state(self) -> ST:
        """Returns a copy of the current node state."""
        return deepcopy(self._state_manager.current_state)

    @property
    def version(self) -> RaidenDBVersion:
        return self.storage.get_version()
