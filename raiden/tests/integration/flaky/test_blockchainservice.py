# -*- coding: utf-8 -*-
from binascii import unhexlify
import logging

import pytest
from ethereum.tools._solidity import compile_file
from ethereum.utils import normalize_address

from raiden.blockchain.abi import CONTRACT_MANAGER, CONTRACT_CHANNEL_MANAGER
from raiden.network.rpc.client import JSONRPCClient
from raiden.utils import privatekey_to_address, get_contract_path, topic_decoder

log = logging.getLogger(__name__)


@pytest.mark.xfail(reason='Some issues in this test, see raiden #691')
@pytest.mark.parametrize('number_of_nodes', [3])
def test_blockchain(
        blockchain_backend,  # required to start the geth backend pylint: disable=unused-argument
        blockchain_rpc_ports,
        private_keys,
        poll_timeout):
    # pylint: disable=too-many-locals

    addresses = [
        privatekey_to_address(priv)
        for priv in private_keys
    ]

    privatekey = private_keys[0]
    address = privatekey_to_address(privatekey)
    total_token = 100

    host = '127.0.0.1'
    jsonrpc_client = JSONRPCClient(
        host,
        blockchain_rpc_ports[0],
        privatekey,
    )

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    humantoken_contracts = compile_file(humantoken_path, libraries=dict())
    token_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'HumanStandardToken',
        humantoken_contracts,
        list(),
        (total_token, 'raiden', 2, 'Rd'),
        contract_path=humantoken_path,
        timeout=poll_timeout,
    )

    registry_path = get_contract_path('Registry.sol')
    registry_contracts = compile_file(registry_path)
    registry_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'Registry',
        registry_contracts,
        list(),
        tuple(),
        contract_path=registry_path,
        timeout=poll_timeout,
    )

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert not log_list

    assert token_proxy.call('balanceOf', address) == total_token
    transaction_hash = registry_proxy.transact(
        'addToken',
        token_proxy.contract_address,
    )
    jsonrpc_client.poll(unhexlify(transaction_hash), timeout=poll_timeout)

    assert len(registry_proxy.call('tokenAddresses')) == 1

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 1

    channel_manager_address_encoded = registry_proxy.call(
        'channelManagerByToken',
        token_proxy.contract_address,
    )
    channel_manager_address = normalize_address(channel_manager_address_encoded)

    log_topics = [
        topic_decoder(topic)
        for topic in log_list[0]['topics']  # pylint: disable=invalid-sequence-index
    ]
    log_data = log_list[0]['data']  # pylint: disable=invalid-sequence-index
    event = registry_proxy.translator.decode_event(
        log_topics,
        unhexlify(log_data[2:]),
    )

    assert channel_manager_address == normalize_address(event['channel_manager_address'])
    assert token_proxy.contract_address == normalize_address(event['token_address'])

    channel_manager_proxy = jsonrpc_client.new_contract_proxy(
        CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER),
        channel_manager_address,
    )

    transaction_hash = channel_manager_proxy.transact(
        'newChannel',
        addresses[1],
        10,
    )
    jsonrpc_client.poll(unhexlify(transaction_hash), timeout=poll_timeout)

    log_list = jsonrpc_client.call(
        'eth_getLogs',
        {
            'fromBlock': '0x0',
            'toBlock': 'latest',
            'topics': [],
        },
    )
    assert len(log_list) == 2
