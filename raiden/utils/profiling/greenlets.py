from typing import Any

import greenlet
import structlog

log = structlog.get_logger(__name__)


def install_switch_log():
    # Do not overwrite the previuos installed tracing function, this could be
    # another profiling tool, and if the callback is overwriten the tool would
    # not work as expected (e.g. a trace sampler)
    previous_callback = greenlet.gettrace()

    def log_every_switch(event: str, args: Any) -> None:
        if event == "switch":
            origin, target = args
            log.debug("Switching", origin=origin, target=target)

        if event == "throw":
            origin, target = args
            log.debug("Throwing", origin=origin, target=target)

        if previous_callback is not None:
            return previous_callback(event, args)

        return None

    greenlet.settrace(log_every_switch)

    return previous_callback


class SwitchMonitoring:
    def __init__(self) -> None:
        self.previous_callback = install_switch_log()

    def stop(self) -> None:
        # This is a best effort only. It is possible for another tracing function
        # to be installed after the `install_switch_log` is called, and this would
        # overwrite it.
        greenlet.settrace(self.previous_callback)
