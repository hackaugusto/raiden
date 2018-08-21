import binascii
import dataclasses
import enum
import inspect
import types
import typing

# Abstract types are not allowed because it's not known which of the concrete
# types should be used, e.g. Collection could be a Dict, List, Set, etc..
#
# Container classes like dict, list, set are also not allowed, since these are
# missing type information for the values in the container
GENERIC_TYPES = (
    dict,
    list,
    set,
    frozenset,

    typing.Any,
    typing.Collection,
    typing.Generic,
    typing.SupportsInt,
    typing.SupportsFloat,
    typing.SupportsComplex,
    typing.SupportsBytes,
    typing.SupportsAbs,
    typing.SupportsRound,
    typing.Hashable,
    typing.Sized,
    typing.AbstractSet,
    typing.MutableSet,
    typing.Mapping,
    typing.MutableMapping,
    typing.Sequence,
    typing.MutableSequence,
)


class _InitVarMeta(type):
    def __getitem__(cls, params):
        return InitVar(params)


class InitVar(metaclass=_InitVarMeta):
    __slots__ = ('type', )

    def __init__(self, type_):
        self.type = type_


def _is_initvar(a_type, dataclasses):  # pylint: disable=redefined-outer-name
    return type(a_type) is dataclasses.InitVar


# For the monkey patch to work this module must be imported before dataclasses
# is used in the application
#
# Monkey patch InitVar to *not* erase the type information
dataclasses.InitVar = InitVar
dataclasses._is_initvar = _is_initvar  # pylint: disable=protected-access


def is_newtype(type_):
    # Both isinstance and issubclass, as well as subclassing will fail for
    # NewType('Derived', Base) since function objects don't support these
    # operations.
    return (
        isinstance(type_, types.FunctionType) and
        hasattr(type_, '__supertype__')
    )


def _handle_list(value, klass: typing.List):
    type_ = klass.__args__[0]

    return [
        object_mapper(entry, type_)
        for entry in value
    ]


def _handle_dict(value, klass: typing.Dict):
    key_type = klass.__args__[0]
    val_type = klass.__args__[1]

    return {
        object_mapper(key, key_type): object_mapper(value, val_type)
        for key, value in value.items()
    }


def _handle_dataclass(value, klass):
    msg = f'cant deserialized {klass} because its missing type annotations'
    assert hasattr(klass, '__annotations__'), msg

    # Because of field(init=False) klass.__annotations__ cannot be used
    argspec = inspect.getfullargspec(klass.__init__)
    annotations = argspec.annotations
    invalid_fields = set(value).difference(annotations)
    assert not invalid_fields, f'JSON contains unknown fields {invalid_fields}'

    args = {
        name: object_mapper(value, annotations[name])
        for name, value in value.items()
    }
    return klass(**args)


def object_mapper(value, klass):
    """ object-mapper from JSON to python classes.

    This function will recursively build python objects out of a JSON file and
    a initial type.
    """
    assert klass not in GENERIC_TYPES, f'Cannot map to {klass}'

    # https://github.com/python/typing/issues/136#issuecomment-138392956
    # Translate a type into a class to do the type checks
    klass_ = getattr(klass, '__origin__', None) or klass

    if is_newtype(klass_):
        result = object_mapper(value, klass.__supertype__)
    elif _is_initvar(klass_, dataclasses):  # test against our patched version
        result = object_mapper(value, klass.type)

    elif klass_ is bytes:
        result = binascii.unhexlify(value)
    elif klass_ is bool:
        assert isinstance(value, bool)
        result = value
    elif klass_ in (int, float):
        result = klass_(value)

    elif issubclass(klass_, enum.Enum):
        result = klass(value)
    elif issubclass(klass_, list):
        result = _handle_list(value, klass)
    elif issubclass(klass_, dict):
        result = _handle_dict(value, klass)
    else:
        result = _handle_dataclass(value, klass)

    return result
