def enable_gevent_monitoring_signal():
    """ Install a signal handler for SIGUSR1 that executes gevent.util.print_run_info().
    This can help evaluating the gevent greenlet tree.
    See http://www.gevent.org/monitoring.html for more information.

    Usage:
        pytest [...]
        # while test is running (or stopped in a pdb session):
        kill -SIGUSR1 $(pidof -x pytest)
    """
    import gevent.util
    import signal

    signal.signal(signal.SIGUSR1, gevent.util.print_run_info)
