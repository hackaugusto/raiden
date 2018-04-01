# -*- coding: utf-8 -*-
import gevent
import inspect
import json
import os.path
import py.path
import tempfile
from binascii import hexlify
from collections import namedtuple
from itertools import product

from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.transport import DummyTransport
from raiden.network.utils import get_free_port
from raiden.tests.fixtures import (
    variables,
    tester_chain,
    tester_blockgas_limit,
    wait_for_partners,
)
from raiden.tests.utils.blockchain import (
    GENESIS_STUB,
    DEFAULT_BALANCE_BIN,
    clique_extradata,
    geth_create_blockchain,
)
from raiden.tests.utils.factories import make_privkey_address
from raiden.tests.utils.network import (
    create_apps,
    create_network_channels,
    create_sequential_channels,
)
from raiden.tests.utils.tester_client import tester_deploy_contract, BlockChainServiceTesterMock
from raiden.utils import (
    address_encoder,
    address_decoder,
    fix_tester_storage,
    get_contract_path,
    privatekey_to_address,
)
from raiden.settings import GAS_PRICE

TestSpec = namedtuple(
    'TestSpec',
    (
        'test_function',
        'network_type',
        'number_of_nodes',
        'number_of_tokens',
        'channels_per_node',
        'deposit',
        'reveal_timeout',
        'settle_timeout',
        'transport_class',
        'retry_interval',
        'retries_before_backoff',
        'throttle_capacity',
        'throttle_fill_rate',
        'nat_invitation_timeout',
        'nat_keepalive_retries',
        'nat_keepalive_timeout',
        'token_amount',
    )
)

TestSuite = namedtuple(
    'TestSuite',
    (
        'number_of_nodes',
        'tests_spec',
    )
)


def tokens_total_amount(all_tests_spec):
    tokens_deposit = []
    for spec in all_tests_spec:
        for token_n in range(spec.number_of_tokens):
            total_network = spec.token_amount

            if token_n < len(tokens_deposit):
                tokens_deposit[token_n] = tokens_deposit[token_n] + total_network
            else:
                tokens_deposit.append(total_network)

    return tokens_deposit


def setup_network_channels(
        test_spec,
        network_keys,
        network_addresses,
        tester,
        token_proxies,
        raiden_udp_ports,
        registry_address,
        endpoint_discovery_address,
        tmpdir,
):
    in_memory_database = True
    token_list = token_proxies[:test_spec.number_of_tokens]
    token_contract_addresses = [token.address for token in token_list]

    for node_address in network_addresses:
        total_per_node = 3 * (test_spec.deposit + 1)

        for token in token_list:
            token.transfer(node_address, total_per_node)

    blockchain_services = [
        BlockChainServiceTesterMock(privkey, tester)
        for privkey in network_keys
    ]

    endpoint_discovery_services = [
        ContractDiscovery(chain.node_address, chain.discovery(endpoint_discovery_address))
        for chain in blockchain_services
    ]

    raiden_apps = create_apps(
        blockchain_services,
        endpoint_discovery_services,
        registry_address,
        raiden_udp_ports,
        DummyTransport,  # Do not use a UDP server to avoid port reuse in MacOSX
        test_spec.reveal_timeout,
        test_spec.settle_timeout,
        variables.database_paths(tmpdir, network_keys, in_memory_database),
        test_spec.retry_interval,
        test_spec.retries_before_backoff,
        test_spec.throttle_capacity,
        test_spec.throttle_fill_rate,
        test_spec.nat_invitation_timeout,
        test_spec.nat_keepalive_retries,
        test_spec.nat_keepalive_timeout,
    )

    if test_spec.network_type == 'raiden_network':
        create_network_channels(
            raiden_apps,
            token_contract_addresses,
            test_spec.channels_per_node,
            test_spec.deposit,
            test_spec.settle_timeout,
        )
    elif test_spec.network_type == 'raiden_chain':
        create_sequential_channels(
            raiden_apps,
            token_contract_addresses[0],
            test_spec.channels_per_node,
            test_spec.deposit,
            test_spec.settle_timeout,
        )

    for app in raiden_apps:
        app.stop(leave_channels=False)


def cached_genesis(
        deploy_key_bin,
        private_keys_bin,
        participant_addresses,
        all_test_spec,
        raiden_udp_ports,
        tmpdir,
        random_marker,
        blockgas_limit,
):
    # Add the accounts to the genesis block with a default ether balance
    tester = tester_chain(
        deploy_key_bin,
        private_keys_bin,
        blockgas_limit,
    )

    deploy_service = BlockChainServiceTesterMock(
        deploy_key_bin,
        tester,
    )

    registry_address = tester_deploy_contract(
        tester,
        deploy_key_bin,
        contract_name='Registry',
        contract_path=get_contract_path('Registry.sol'),
    )
    registry = deploy_service.registry(registry_address)

    endpoint_discovery_address = deploy_service.deploy_contract(
        'EndpointRegistry',
        get_contract_path('EndpointRegistry.sol'),
    )

    token_proxies = []
    for i, amount in enumerate(tokens_total_amount(all_test_spec)):
        token_address = deploy_service.deploy_and_register_token(
            registry,
            contract_name='HumanStandardToken',
            contract_path=get_contract_path('HumanStandardToken.sol'),
            constructor_parameters=(amount, f'Raiden{i}', 2, f'RD{i}'),
        )
        token_proxies.append(deploy_service.token(token_address))

    network_start = 0
    for spec in all_test_spec:
        network_end = network_start + spec.number_of_nodes

        network_keys = private_keys_bin[network_start:network_end]
        network_addresses = participant_addresses[network_start:network_end]

        network_start += spec.number_of_nodes

        setup_network_channels(
            spec,
            network_keys,
            network_addresses,
            tester,
            token_proxies,
            raiden_udp_ports,
            registry_address,
            endpoint_discovery_address,
            tmpdir,
        )

    # save the state from the last block into a genesis dict
    tester.mine()

    genesis_alloc = dict()
    for account_address in tester.head_state.to_dict():
        account_alloc = tester.head_state.account_to_dict(account_address)

        # Both keys and values of the account storage associative array
        # must now be encoded with 64 hex digits
        if account_alloc['storage']:
            account_alloc['storage'] = fix_tester_storage(account_alloc['storage'])

        # code must be hex encoded with 0x prefix
        account_alloc['code'] = account_alloc.get('code', '')

        # account_to_dict returns accounts with nonce=0 and the nonce must
        # be encoded with 16 hex digits
        account_alloc['nonce'] = '0x%016x' % tester.head_state.get_nonce(account_address)

        genesis_alloc[account_address] = account_alloc

    all_keys = set(private_keys_bin)
    all_keys.add(deploy_key_bin)
    all_keys = sorted(all_keys)
    account_addresses = [
        privatekey_to_address(key)
        for key in all_keys
    ]

    for address in account_addresses:
        address_hex = hexlify(address).decode()
        genesis_alloc[address_hex]['balance'] = DEFAULT_BALANCE_BIN

    genesis = GENESIS_STUB.copy()
    genesis['config']['clique'] = {'period': 1, 'epoch': 30000}

    random_marker = random_marker
    genesis['extraData'] = clique_extradata(
        random_marker,
        address_encoder(account_addresses[0])[2:],
    )
    genesis['alloc'] = genesis_alloc
    genesis['config']['defaultDiscoveryAddress'] = address_encoder(endpoint_discovery_address)
    genesis['config']['defaultRegistryAddress'] = address_encoder(registry_address)
    genesis['config']['tokenAddresses'] = [
        address_encoder(token.address)
        for token in token_proxies
    ]

    return genesis


def get_test_cases(test_functions):
    number_of_nodes = 0
    number_of_tokens = 0
    all_test_spec = []

    for test_function in test_functions:

        arguments = inspect.getargs(test_function.__code__).args
        if 'raiden_network' in arguments:
            network_type = 'raiden_network'
        elif 'raiden_chain' in arguments:
            network_type = 'raiden_chain'

        # Set the parameters to the default values
        #
        # Ignore these fixtures:
        # - blockchain_cache
        # - cached_genesis
        # - both_participants_deposit
        # - register_tokens
        # - privatekey_seed
        # - transferred_amount
        # - transport_class
        # - tree
        # - fee
        # - identifier
        # - nonce
        # - token_amount (computed bellow)
        parameters = {
            'channels_per_node': [variables.channels_per_node()],
            'number_of_nodes': [variables.number_of_nodes()],
            'number_of_tokens': [variables.number_of_tokens()],
            'deposit': [variables.deposit()],
            'reveal_timeout': [variables.reveal_timeout()],
            'settle_timeout': [variables.settle_timeout()],
            'retry_interval': [variables.retry_interval()],
            'retries_before_backoff': [variables.retries_before_backoff()],
            'throttle_capacity': [variables.throttle_capacity()],
            'throttle_fill_rate': [variables.throttle_fill_rate()],
            'transport_class': [variables.transport_class()],
            'nat_invitation_timeout': [variables.nat_invitation_timeout()],
            'nat_keepalive_retries': [variables.nat_keepalive_retries()],
            'nat_keepalive_timeout': [variables.nat_keepalive_timeout()],
        }

        for mark in test_function.pytestmark:
            if not mark.name == 'parametrize':
                continue

            # overwrite the default parameters with the values define in
            # @pytest.mark.parametrize
            if mark.args[0] in parameters:
                parameters[mark.args[0]] = mark.args[1]

        # Each possible combination of parameters is a different test, compute
        # the test runs

        # [(name, [values])...] => [[(name, value)...],...]
        flat_parameters = [
            [(name, value) for value in values]
            for name, values in parameters.items()
        ]

        # The produce of the parameters made valid tests
        all_configurations = product(*flat_parameters)

        for config_parameters in all_configurations:
            config = dict(config_parameters)
            number_of_nodes += config['number_of_nodes']
            number_of_tokens = max(config['number_of_tokens'], number_of_tokens)

            token_amount = variables.token_amount(config['number_of_nodes'], config['deposit'])
            spec = TestSpec(
                test_function,
                network_type,
                config['number_of_nodes'],
                config['number_of_tokens'],
                config['channels_per_node'],
                config['deposit'],
                config['reveal_timeout'],
                config['settle_timeout'],
                config['transport_class'],
                config['retry_interval'],
                config['retries_before_backoff'],
                config['throttle_capacity'],
                config['throttle_fill_rate'],
                config['nat_invitation_timeout'],
                config['nat_keepalive_retries'],
                config['nat_keepalive_timeout'],
                token_amount,
            )
            all_test_spec.append(spec)

    return TestSuite(number_of_nodes, all_test_spec)


def setup_blockchain(test_functions, tmpdir, port_generator, random_marker):
    private_keys = []
    addresses = []

    test_suite = get_test_cases(test_functions)

    for _ in range(test_suite.number_of_nodes):
        privkey, address = make_privkey_address()
        private_keys.append(privkey)
        addresses.append(address)

    deploy_key, _ = make_privkey_address()
    private_keys_bin = [
        coincurve_key.secret
        for coincurve_key in private_keys
    ]

    genesis = cached_genesis(
        deploy_key.secret,
        private_keys_bin,
        addresses,
        test_suite.tests_spec,
        variables.raiden_udp_ports(test_suite.number_of_nodes, port_generator),
        tmpdir,
        random_marker,
        tester_blockgas_limit(),
    )

    return deploy_key, private_keys, genesis, test_suite


def main(test_functions):
    tmpdir_manager = tempfile.TemporaryDirectory()
    tmpdir = py.path.local(tmpdir_manager.name)

    port_generator = get_free_port('127.0.0.1', 4000)
    random_marker = variables.random_marker()
    deploy_key, private_keys, genesis, test_suite = setup_blockchain(
        test_functions,
        tmpdir,
        port_generator,
        random_marker,
    )
    genesis_path = os.path.join(str(tmpdir), 'generated_genesis.json')
    deploy_key_bin = deploy_key.secret
    private_keys_bin = [key.secret for key in private_keys]

    with open(genesis_path, 'w') as handler:
        json.dump(genesis, handler)

    blockchain_number_of_nodes = variables.blockchain_number_of_nodes()
    blockchain_rpc_ports = variables.blockchain_rpc_ports(
        blockchain_number_of_nodes,
        port_generator,
    )
    blockchain_p2p_ports = variables.blockchain_p2p_ports(
        blockchain_number_of_nodes,
        port_generator,
    )
    blockchain_private_keys = variables.blockchain_private_keys(
        blockchain_number_of_nodes,
        variables.blockchain_key_seed(),
    )

    host = '0.0.0.0'
    rpc_port = blockchain_rpc_ports[0]
    deploy_client = JSONRPCClient(
        host,
        rpc_port,
        deploy_key_bin,
    )

    verbose = 0
    geth_processes = geth_create_blockchain(
        deploy_key_bin,
        deploy_client,
        private_keys_bin,
        blockchain_private_keys,
        blockchain_rpc_ports,
        blockchain_p2p_ports,
        str(tmpdir),
        verbose,
        random_marker,
        genesis_path,
    )

    network_start = 0
    rpc_port = blockchain_rpc_ports[0]
    greenlets = []

    token_addresses = [
        address_decoder(token_address)
        for token_address in genesis['config']['tokenAddresses']
    ]
    registry_address = address_decoder(genesis['config']['defaultRegistryAddress'])
    discovery_address = address_decoder(genesis['config']['defaultDiscoveryAddress'])

    for spec in test_suite.tests_spec:
        network_end = network_start + spec.number_of_nodes
        test_privkeys_bin = private_keys_bin[network_start:network_end]

        network_start += spec.number_of_nodes

        task = gevent.spawn(
            run_test,
            spec,
            test_privkeys_bin,
            token_addresses,
            rpc_port,
            registry_address,
            discovery_address,
            port_generator,
            tmpdir,
        )
        greenlets.append(task)

    gevent.wait(greenlets)

    for process in geth_processes:
        process.terminate()


def instantiate_apps(
        spec,
        private_keys_bin,
        rpc_port,
        registry_address,
        endpoint_discovery_address,
        port_generator,
        tmpdir,
):
    host = '0.0.0.0'
    blockchain_services = list()
    for privkey in private_keys_bin:
        rpc_client = JSONRPCClient(
            host,
            rpc_port,
            privkey,
        )

        blockchain = BlockChainService(
            privkey,
            rpc_client,
            GAS_PRICE,
        )
        blockchain_services.append(blockchain)

    endpoint_discovery_services = [
        ContractDiscovery(
            chain.node_address,
            chain.discovery(endpoint_discovery_address),
        )
        for chain in blockchain_services
    ]

    in_memory_database = True
    database_paths = variables.database_paths(tmpdir, private_keys_bin, in_memory_database)

    raiden_apps = create_apps(
        blockchain_services,
        endpoint_discovery_services,
        registry_address,
        variables.raiden_udp_ports(spec.number_of_nodes, port_generator),
        spec.transport_class,
        spec.reveal_timeout,
        spec.settle_timeout,
        database_paths,
        spec.retry_interval,
        spec.retries_before_backoff,
        spec.throttle_capacity,
        spec.throttle_fill_rate,
        spec.nat_invitation_timeout,
        spec.nat_keepalive_retries,
        spec.nat_keepalive_timeout,
    )

    for app in raiden_apps:
        app.raiden.register_payment_network(app.raiden.default_registry.address)

    wait_for_partners(raiden_apps)

    return raiden_apps


def run_test(
        spec,
        private_keys_bin,
        token_addresses,
        rpc_port,
        registry_address,
        endpoint_discovery_address,
        port_generator,
        tmpdir,
):
    argspec = inspect.getargs(spec.test_function.__code__)

    is_chain = 'raiden_chain' in argspec.args
    is_network = 'raiden_network' in argspec.args

    fixtures = spec._asdict()

    if is_chain or is_network:
        apps = instantiate_apps(
            spec,
            private_keys_bin,
            rpc_port,
            registry_address,
            endpoint_discovery_address,
            port_generator,
            tmpdir,
        )

        if is_chain:
            fixtures['raiden_chain'] = apps
        elif is_network:
            fixtures['raiden_network'] = apps

    fixtures['token_addresses'] = token_addresses[:spec.number_of_tokens]

    arguments = [fixtures[arg] for arg in argspec.args]
    spec.test_function(*arguments)


if __name__ == '__main__':
    from raiden.tests.integration import (
        test_blockchainservice,
        # test_echo_node,
        # test_endpointregistry,
        # test_events,
        # test_pythonapi,
        # test_regression,
        # test_transfer,
    )
    ALL_TESTS = [
        test_blockchainservice.test_new_netting_contract,
        test_blockchainservice.test_channelmanager_graph_building,
        test_blockchainservice.test_channel_with_self,
        # test_echo_node,
        # test_endpointregistry,
        # test_events,
        # test_pythonapi,
        # test_regression,
        # test_transfer,
    ]

    main(ALL_TESTS)
