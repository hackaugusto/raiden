from raiden.raiden_service import RaidenService
from raiden.transfer import channel
from raiden.transfer.canonical_identifier import CanonicalIdentifier
from raiden.transfer.state import NettingChannelState
from raiden.transfer.views import get_channelstate_by_canonical_identifier, state_from_raiden
from raiden.utils.typing import Optional


def get_channel_if_at_state(
    raiden: RaidenService, canonical_identifier: CanonicalIdentifier, state: str
) -> Optional[NettingChannelState]:
    """Wait until the channel with partner_address is registered."""
    channel_state = get_channelstate_by_canonical_identifier(
        state_from_raiden(raiden), canonical_identifier
    )

    if channel_state is not None and channel.get_status(channel_state) == state:
        return channel_state

    return None
