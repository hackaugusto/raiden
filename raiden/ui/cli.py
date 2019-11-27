import contextlib
import json
import os
import signal
import sys
import textwrap
import traceback
from copy import deepcopy
from io import StringIO
from subprocess import TimeoutExpired
from tempfile import mkdtemp, mktemp
from typing import Any, AnyStr, Callable, ContextManager, Dict, List, Optional, Tuple

import click
import structlog
from click import Context
from requests.packages import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from raiden.app import App
from raiden.constants import (
    DISCOVERY_DEFAULT_ROOM,
    FLAT_MED_FEE_MIN,
    IMBALANCE_MED_FEE_MAX,
    IMBALANCE_MED_FEE_MIN,
    PROPORTIONAL_MED_FEE_MAX,
    PROPORTIONAL_MED_FEE_MIN,
    EthClient,
    RoutingMode,
)
from raiden.exceptions import EthereumNonceTooLow, ReplacementTransactionUnderpriced
from raiden.log_config import configure_logging
from raiden.network.transport.matrix.utils import make_room_alias
from raiden.network.utils import get_free_port
from raiden.settings import (
    DEFAULT_BLOCKCHAIN_QUERY_INTERVAL,
    DEFAULT_HTTP_SERVER_PORT,
    DEFAULT_PATHFINDING_IOU_TIMEOUT,
    DEFAULT_PATHFINDING_MAX_FEE,
    DEFAULT_PATHFINDING_MAX_PATHS,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
    RAIDEN_CONTRACT_VERSION,
)
from raiden.utils import get_system_spec
from raiden.utils.cli import (
    ADDRESS_TYPE,
    LOG_LEVEL_CONFIG_TYPE,
    EnumChoiceType,
    GasPriceChoiceType,
    PathRelativePath,
    apply_config_file,
    group,
    option,
    option_group,
)
from raiden.utils.http import HTTPExecutor
from raiden.utils.typing import MYPY_ANNOTATION, TokenAddress
from raiden_contracts.constants import NETWORKNAME_TO_ID

from .runners import EchoNodeRunner, MatrixRunner

log = structlog.get_logger(__name__)


OPTION_DEPENDENCIES: Dict[str, List[Tuple[str, Any]]] = {
    "pathfinding-service-address": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-max-paths": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-max-fee": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-iou-timeout": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "enable-monitoring": [("transport", "matrix")],
    "matrix-server": [("transport", "matrix")],
}


def options(func: Callable) -> Callable:
    """Having the common app options as a decorator facilitates reuse."""

    # Until https://github.com/pallets/click/issues/926 is fixed the options need to be re-defined
    # for every use
    options_ = [
        option("--version", hidden=True, is_flag=True, allow_from_autoenv=False),
        option(
            "--datadir",
            help="Directory for storing raiden data.",
            default=lambda: os.path.join(os.path.expanduser("~"), ".raiden"),
            type=click.Path(
                exists=False,
                dir_okay=True,
                file_okay=False,
                writable=True,
                resolve_path=True,
                allow_dash=False,
            ),
            show_default=True,
        ),
        option(
            "--config-file",
            help="Configuration file (TOML)",
            default=os.path.join("${datadir}", "config.toml"),
            type=PathRelativePath(
                file_okay=True, dir_okay=False, exists=False, readable=True, resolve_path=True
            ),
            show_default=True,
        ),
        option(
            "--keystore-path",
            help=(
                "If you have a non-standard path for the ethereum keystore directory"
                " provide it using this argument."
            ),
            default=None,
            type=click.Path(exists=True),
            show_default=True,
        ),
        option(
            "--address",
            help=(
                "The ethereum address you would like raiden to use and for which "
                "a keystore file exists in your local system."
            ),
            default=None,
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            "--password-file",
            help="Text file containing the password for the provided account",
            default=None,
            type=click.File(lazy=True),
            show_default=True,
        ),
        option("--console", help="Start the interactive raiden console", is_flag=True),
        option(
            "--accept-disclaimer",
            help="Bypass the experimental software disclaimer prompt",
            is_flag=True,
        ),
        option(
            "--showconfig",
            help="Show all configuration values used to control Raiden's behavior",
            is_flag=True,
        ),
        option(
            "--blockchain-query-interval",
            help="Time interval after which to check for new blocks (in seconds)",
            default=DEFAULT_BLOCKCHAIN_QUERY_INTERVAL,
            show_default=True,
            type=click.FloatRange(min=0.1),
        ),
        option_group(
            "Channel-specific Options",
            option(
                "--default-reveal-timeout",
                help="Sets the default reveal timeout to be used to newly created channels",
                default=DEFAULT_REVEAL_TIMEOUT,
                show_default=True,
                type=click.IntRange(min=20),
            ),
            option(
                "--default-settle-timeout",
                help="Sets the default settle timeout to be used to newly created channels",
                default=DEFAULT_SETTLE_TIMEOUT,
                show_default=True,
                type=click.IntRange(min=20),
            ),
        ),
        option_group(
            "Ethereum Node Options",
            option(
                "--sync-check/--no-sync-check",
                help="Checks if the ethereum node is synchronized against etherscan.",
                default=True,
                show_default=True,
            ),
            option(
                "--gas-price",
                help=(
                    "Set the gas price for ethereum transactions. If not provided "
                    "the normal gas price startegy is used.\n"
                    "Available options:\n"
                    '"fast" - transactions are usually mined within 60 seconds\n'
                    '"normal" - transactions are usually mined within 5 minutes\n'
                    "<GAS_PRICE> - use given gas price\n"
                ),
                type=GasPriceChoiceType(["normal", "fast"]),
                default="fast",
                show_default=True,
            ),
            option(
                "--eth-rpc-endpoint",
                help=(
                    '"host:port" address of ethereum JSON-RPC server.\n'
                    "Also accepts a protocol prefix (http:// or https://) with optional port"
                ),
                default="http://127.0.0.1:8545",  # geth default jsonrpc port
                type=str,
                show_default=True,
            ),
        ),
        option_group(
            "Raiden Services Options",
            option(
                "--pathfinding-max-paths",
                help="Set maximum number of paths to be requested from the path finding service.",
                default=DEFAULT_PATHFINDING_MAX_PATHS,
                type=int,
                show_default=True,
            ),
            option(
                "--pathfinding-max-fee",
                help="Set max fee per request paid to the path finding service.",
                default=DEFAULT_PATHFINDING_MAX_FEE,
                type=int,
                show_default=True,
            ),
            option(
                "--pathfinding-iou-timeout",
                help="Number of blocks before a new IOU to the path finding service expires.",
                default=DEFAULT_PATHFINDING_IOU_TIMEOUT,
                type=int,
                show_default=True,
            ),
        ),
        option_group(
            "Logging Options",
            option(
                "--log-config",
                help="Log level configuration.\n"
                "Format: [<logger-name-1>]:<level>[,<logger-name-2>:level][,...]",
                type=LOG_LEVEL_CONFIG_TYPE,
                default=":info",
                show_default=True,
            ),
            option(
                "--log-file",
                help="file path for logging to file",
                default=None,
                type=click.Path(dir_okay=False, writable=True, resolve_path=True),
                show_default=True,
            ),
            option("--log-json", help="Output log lines in JSON format", is_flag=True),
            option(
                "--debug-logfile-path",
                help=(
                    "The absolute path to the debug logfile. If not given defaults to:\n"
                    " - OSX: ~/Library/Logs/Raiden/raiden_debug_XXX.log\n"
                    " - Windows: ~/Appdata/Roaming/Raiden/raiden_debug_XXX.log\n"
                    " - Linux: ~/.raiden/raiden_debug_XXX.log\n"
                    "\nIf there is a problem with expanding home it is placed under /tmp"
                ),
                type=click.Path(dir_okay=False, writable=True, resolve_path=True),
            ),
            option(
                "--disable-debug-logfile",
                help=(
                    "Disable the debug logfile feature. This is independent of "
                    "the normal logging setup"
                ),
                is_flag=True,
            ),
        ),
        option_group(
            "RPC Options",
            option(
                "--rpc/--no-rpc",
                help="Start with or without the RPC server.",
                default=True,
                show_default=True,
            ),
            option(
                "--rpccorsdomain",
                help="Comma separated list of domains to accept cross origin requests.",
                default="http://localhost:*/*",
                type=str,
                show_default=True,
            ),
            option(
                "--api-address",
                help='"host:port" for the RPC server to listen on.',
                default=f"127.0.0.1:{DEFAULT_HTTP_SERVER_PORT}",
                type=str,
                show_default=True,
            ),
            option(
                "--web-ui/--no-web-ui",
                help=(
                    "Start with or without the web interface. Requires --rpc. "
                    "It will be accessible at http://<api-address>. "
                ),
                default=True,
                show_default=True,
            ),
        ),
        option_group(
            "Mediation Fee Options",
            option(
                "--flat-fee",
                help=(
                    "Sets the flat fee required for every mediation in wei of the "
                    "mediated token for a certain token address. Must be bigger "
                    f"or equal to {FLAT_MED_FEE_MIN}."
                ),
                type=(ADDRESS_TYPE, click.IntRange(min=FLAT_MED_FEE_MIN)),
                multiple=True,
            ),
            option(
                "--proportional-fee",
                help=(
                    "Mediation fee as ratio of mediated amount in parts-per-million "
                    "(10^-6) for a certain token address. "
                    f"Must be in [{PROPORTIONAL_MED_FEE_MIN}, {PROPORTIONAL_MED_FEE_MAX}]."
                ),
                type=(
                    ADDRESS_TYPE,
                    click.IntRange(min=PROPORTIONAL_MED_FEE_MIN, max=PROPORTIONAL_MED_FEE_MAX),
                ),
                multiple=True,
            ),
            option(
                "--proportional-imbalance-fee",
                help=(
                    "Set the worst-case imbalance fee relative to the channels capacity "
                    "in parts-per-million (10^-6) for a certain token address. "
                    f"Must be in [{IMBALANCE_MED_FEE_MIN}, {IMBALANCE_MED_FEE_MAX}]."
                ),
                type=(
                    ADDRESS_TYPE,
                    click.IntRange(min=IMBALANCE_MED_FEE_MIN, max=IMBALANCE_MED_FEE_MAX),
                ),
                multiple=True,
            ),
            option(
                "--cap-mediation-fees/--no-cap-mediation-fees",
                help="Cap the mediation fees to never get negative.",
                default=True,
                show_default=True,
            ),
        ),
    ]

    for option_ in reversed(options_):
        func = option_(func)
    return func


@group(invoke_without_command=True, context_settings={"max_content_width": 120})
@options
@click.pass_context
def run(ctx: Context, **kwargs: Any) -> None:
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if kwargs.pop("version", False):
        click.echo(
            click.style("Hint: Use ", fg="green")
            + click.style(f"'{os.path.basename(sys.argv[0])} version'", fg="yellow")
            + click.style(" instead", fg="green")
        )
        ctx.invoke(version, short=True)
        return

    if kwargs["config_file"]:
        apply_config_file(run, kwargs, ctx)

    if ctx.invoked_subcommand is not None:
        # Pass parsed args on to subcommands.
        ctx.obj = kwargs
        return

    runner = MatrixRunner(kwargs, ctx)
    click.secho(runner.welcome_string, fg="green")
    click.secho(
        textwrap.dedent(
            """\
            ----------------------------------------------------------------------
            | This is an Alpha version of experimental open source software      |
            | released as a test version under an MIT license and may contain    |
            | errors and/or bugs. No guarantee or representations whatsoever is  |
            | made regarding its suitability (or its use) for any purpose or     |
            | regarding its compliance with any applicable laws and regulations. |
            | Use of the software is at your own risk and discretion and by      |
            | using the software you acknowledge that you have read this         |
            | disclaimer, understand its contents, assume all risk related       |
            | thereto and hereby release, waive, discharge and covenant not to   |
            | sue Brainbot Labs Establishment or any officers, employees or      |
            | affiliates from and for any direct or indirect liability resulting |
            | from the use of the software as permissible by applicable laws and |
            | regulations.                                                       |
            |                                                                    |
            | Privacy Warning: Please be aware, that by using the Raiden Client, |
            | among others, your Ethereum address, channels, channel deposits,   |
            | settlements and the Ethereum address of your channel counterparty  |
            | will be stored on the Ethereum chain, i.e. on servers of Ethereum  |
            | node operators and ergo are to a certain extent publicly available.|
            | The same might also be stored on systems of parties running Raiden |
            | nodes connected to the same token network. Data present in the     |
            | Ethereum chain is very unlikely to be able to be changed, removed  |
            | or deleted from the public arena.                                  |
            |                                                                    |
            | Also be aware, that data on individual Raiden token transfers will |
            | be made available via the Matrix protocol to the recipient,        |
            | intermediating nodes of a specific transfer as well as to the      |
            | Matrix server operators.                                           |
            ----------------------------------------------------------------------"""
        ),
        fg="yellow",
    )
    if not kwargs["accept_disclaimer"]:
        click.confirm(
            "\nHave you read, understood and hereby accept the above "
            "disclaimer and privacy warning?",
            abort=True,
        )

    # TODO:
    # - Ask for confirmation to quit if there are any locked transfers that did
    # not timeout.
    try:
        app = runner.run()
        app.stop()
    except (ReplacementTransactionUnderpriced, EthereumNonceTooLow) as e:
        click.secho(
            "{}. Please make sure that this Raiden node is the "
            "only user of the selected account".format(str(e)),
            fg="red",
        )
        sys.exit(1)


# List of available options, used by the scenario player
FLAG_OPTIONS = {param.name.replace("_", "-") for param in run.params if param.is_flag}
FLAG_OPTIONS = FLAG_OPTIONS.union({"no-" + opt for opt in FLAG_OPTIONS})
KNOWN_OPTIONS = {param.name.replace("_", "-") for param in run.params}.union(FLAG_OPTIONS)


@run.command()
@option("--short", is_flag=True, help="Only display Raiden version")
def version(short: bool) -> None:
    """Print version information and exit. """
    if short:
        print(get_system_spec()["raiden"])
    else:
        print(json.dumps(get_system_spec(), indent=2))
