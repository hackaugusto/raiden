from raiden.transfer.architecture import State, StateChange, TransitionResult
from raiden.utils.typing import Callable, Tuple, TypeVar, overload, Dict, Union

S = TypeVar("S", bound=State)
K = TypeVar("K")
V = TypeVar("V")

# The node state has to be a tree datastructure (this is not automatically
# enforced). Cycles are not allowed to simplify serialization to flat formats
# (e.g. JSON).
#
# Because of this if an object has more than one name a mapping is needed.
# These maps are called named links, and are used to translate a second name to
# the canonical name. The container which stores the object which its canonical
# identifier is called its environment.

# Both updates have the same shape to allow for generic code.
NameUpdate = Tuple[Dict[K, V], K, V]
EnvironmentName = Tuple[Dict[K, S], K]
EnvironmentUpdate = Tuple[Dict[K, S], K, S]

# Type variables for variadicic functions
T1 = TypeVar("T1")
T2 = TypeVar("T2")
T3 = TypeVar("T3")
T4 = TypeVar("T4")
T5 = TypeVar("T5")
T6 = TypeVar("T6")
V1 = TypeVar('V1')
V2 = TypeVar('V2')
V3 = TypeVar('V3')
V4 = TypeVar('V4')

# By definition a named link is mapping a origin to destination, which are
# likely different. For this reason a container where individual elements can
# be type check is needed, and this is only possible with a fixed length
# immutable container (a tuple).
MultipleLinkUpdates = Union[
    Tuple[EnvironmentUpdate[T1, V1]],
    Tuple[EnvironmentUpdate[T1, V1], NameUpdate[T2, V2]],
    Tuple[EnvironmentUpdate[T1, V1], NameUpdate[T2, V2], NameUpdate[T3, V3]],
    Tuple[EnvironmentUpdate[T1, V1], NameUpdate[T2, V2], NameUpdate[T3, V3], NameUpdate[T4, V4]],
]


def update_environments(
    transition: TransitionResult,
    updates: MultipleLinkUpdates,
):
    # The `transition` is required to enforce a consistent update on all
    # containers, and to only allow an update after a subdispatch.

    # A transition to `None` means the subtask is finished, the references must
    # be cleared.
    if transition.new_state is None:
        for container, key, _ in updates:
            # If initialization failed no container will not have the key.
            if key in container:
                del container[key]
    else:
        container, key, value = updates[0]
        container[key] = value

        for container, key, value in updates[1:]:
            msg = (
                'Named links by definition point to the canonical identifier, '
                'therefore they must not change.'
            )
            assert container.get(key, value) == value, msg
            container[key] = value


@overload  # noqa
def subdispatch(
    state_transition: Callable[[S, StateChange], TransitionResult[S]],
    current_state: State,
    # fourth argument is optional
) -> TransitionResult[S]:
    # pylint: disable=unused-argument,pointless-statement
    ...


@overload  # noqa
def subdispatch(
    state_transition: Callable[[S, StateChange], TransitionResult[S]],
    current_state: State,
    args: Tuple[()],  # default value
) -> TransitionResult[S]:
    # pylint: disable=unused-argument,pointless-statement,function-redefined
    ...


@overload  # noqa
def subdispatch(
    state_transition: Callable[[S, StateChange, T1], TransitionResult[S]],
    current_state: State,
    args: Tuple[T1],
) -> TransitionResult[S]:
    # pylint: disable=unused-argument,pointless-statement,function-redefined
    ...


@overload  # noqa
def subdispatch(
    state_transition: Callable[[S, StateChange, T1, T2], TransitionResult[S]],
    current_state: State,
    args: Tuple[T1, T2],
) -> TransitionResult[S]:
    # pylint: disable=unused-argument,pointless-statement,function-redefined,function-redefined
    ...


@overload  # noqa
def subdispatch(
    state_transition: Callable[[S, StateChange, T1, T2, T3], TransitionResult[S]],
    current_state: State,
    args: Tuple[T1, T2, T3],
) -> TransitionResult[S]:
    # pylint: disable=unused-argument,pointless-statement,function-redefined,function-redefined
    ...


@overload  # noqa
def subdispatch(
    state_transition: Callable[[S, StateChange, T1, T2, T3, T4], TransitionResult[S]],
    current_state: State,
    args: Tuple[T1, T2, T3, T4],
) -> TransitionResult[S]:
    # pylint: disable=unused-argument,pointless-statement,function-redefined,function-redefined
    ...


@overload  # noqa
def subdispatch(
    state_transition: Callable[[S, StateChange, T1, T2, T3, T4, T5], TransitionResult[S]],
    current_state: State,
    args: Tuple[T1, T2, T3, T4, T5],
) -> TransitionResult[S]:
    # pylint: disable=unused-argument,pointless-statement,function-redefined,function-redefined
    ...


@overload  # noqa
def subdispatch(
    state_transition: Callable[[T1, T2, T3, T4, T5, T6], TransitionResult[S]],
    current_state: State,
    args: Tuple[T1, T2, T3, T4, T5, T6],
) -> TransitionResult[S]:
    # pylint: disable=unused-argument,pointless-statement,function-redefined,function-redefined
    ...


def subdispatch(state_transition, current_state, state_change, arguments=()):  # noqa
    # pylint: disable=function-redefined
    transition = state_transition(current_state, state_change, *arguments)
    update_environments(environment, transition)
    return TransitionResult(chain_state, transition.events)
