# -*- coding: utf-8 -*-
import itertools

import pytest
from ethereum.tools import _solidity

from raiden import waiting
from raiden.api.python import RaidenAPI2
from raiden.exceptions import AddressWithoutCode, SamePeerAddress
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.tests.utils.blockchain import wait_until_block
from raiden.transfer import views
from raiden.utils import privatekey_to_address, get_contract_path


solidity = _solidity.get_solidity()   # pylint: disable=invalid-name


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [0])
def test_new_netting_contract(raiden_network, token_amount, settle_timeout):
    # pylint: disable=line-too-long,too-many-statements,too-many-locals
    app0, app1, app2 = raiden_network
    registry_address = app0.raiden.default_registry.address

    peer0_address = app0.raiden.address
    peer1_address = app1.raiden.address
    peer2_address = app2.raiden.address

    blockchain_service0 = app0.raiden.chain
    registry = app0.raiden.default_registry

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    token_address = blockchain_service0.deploy_and_register_token(
        registry,
        contract_name='HumanStandardToken',
        contract_path=humantoken_path,
        constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
    )

    token0 = blockchain_service0.token(token_address)
    for transfer_to in raiden_network[1:]:
        token0.transfer(
            privatekey_to_address(transfer_to.raiden.privkey),
            token_amount // len(raiden_network),
        )

    manager0 = registry.manager_by_token(token_address)

    # sanity
    assert manager0.channels_addresses() == []
    assert manager0.channels_by_participant(peer0_address) == []
    assert manager0.channels_by_participant(peer1_address) == []
    assert manager0.channels_by_participant(peer2_address) == []

    # create one channel
    netting_address_01 = manager0.new_netting_channel(
        peer1_address,
        settle_timeout,
    )

    # check contract state
    netting_channel_01 = blockchain_service0.netting_channel(netting_address_01)
    assert netting_channel_01.can_transfer() is False

    # check channels
    channel_list = manager0.channels_addresses()
    assert sorted(channel_list[0]) == sorted([peer0_address, peer1_address])

    assert manager0.channels_by_participant(peer0_address) == [netting_address_01]
    assert manager0.channels_by_participant(peer1_address) == [netting_address_01]
    assert manager0.channels_by_participant(peer2_address) == []
    # create a duplicated channel with same participants while previous channel
    #  is still open should throw an exception
    with pytest.raises(Exception):
        manager0.new_netting_channel(
            peer1_address,
            settle_timeout,
        )
    # create other channel
    netting_address_02 = manager0.new_netting_channel(
        peer2_address,
        settle_timeout,
    )

    netting_channel_02 = blockchain_service0.netting_channel(netting_address_02)

    assert netting_channel_02.can_transfer() is False

    channel_list = manager0.channels_addresses()
    expected_channels = [
        sorted([peer0_address, peer1_address]),
        sorted([peer0_address, peer2_address]),
    ]

    for channel in channel_list:
        assert sorted(channel) in expected_channels

    result0 = sorted(manager0.channels_by_participant(peer0_address))
    result1 = sorted([netting_address_01, netting_address_02])
    assert result0 == result1
    assert manager0.channels_by_participant(peer1_address) == [netting_address_01]
    assert manager0.channels_by_participant(peer2_address) == [netting_address_02]

    # deposit without approve should fail
    netting_channel_01.deposit(100)
    assert netting_channel_01.can_transfer() is False
    assert netting_channel_02.can_transfer() is False
    assert netting_channel_01.detail()['our_balance'] == 0
    assert netting_channel_02.detail()['our_balance'] == 0

    # single-funded channel
    app0.raiden.chain.token(token_address).approve(netting_address_01, 100)
    netting_channel_01.deposit(100)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is False

    assert netting_channel_01.detail()['our_balance'] == 100
    assert netting_channel_02.detail()['our_balance'] == 0

    # double-funded channel
    app0.raiden.chain.token(token_address).approve(netting_address_02, 70)
    netting_channel_02.deposit(70)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is True

    assert netting_channel_02.detail()['our_balance'] == 70
    assert netting_channel_02.detail()['partner_balance'] == 0

    app2.raiden.chain.token(token_address).approve(netting_address_02, 130)
    app2.raiden.chain.netting_channel(netting_address_02).deposit(130)
    assert netting_channel_01.can_transfer() is True
    assert netting_channel_02.can_transfer() is True

    assert netting_channel_02.detail()['our_balance'] == 70
    assert netting_channel_02.detail()['partner_balance'] == 130

    RaidenAPI2(app1.raiden).channel_close(token_address, app0.raiden.address)

    waiting.wait_for_settle(
        app1.raiden,
        registry_address,
        token_address,
        [netting_address_01],
        app1.raiden.alarm.wait_time,
    )

    with pytest.raises(AddressWithoutCode):
        netting_channel_01.closed()

    with pytest.raises(AddressWithoutCode):
        netting_channel_01.opened()

    # open channel with same peer again
    netting_address_01_reopened = manager0.new_netting_channel(
        peer1_address,
        settle_timeout,
    )
    netting_channel_01_reopened = blockchain_service0.netting_channel(netting_address_01_reopened)

    assert netting_channel_01_reopened.opened() != 0
    assert netting_address_01_reopened in manager0.channels_by_participant(peer0_address)
    assert netting_address_01 not in manager0.channels_by_participant(peer0_address)

    app0.raiden.chain.token(token_address).approve(netting_address_01_reopened, 100)
    netting_channel_01_reopened.deposit(100)
    assert netting_channel_01_reopened.opened() != 0


@pytest.mark.parametrize('number_of_nodes', [10])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channelmanager_graph_building(
        raiden_network,
        token_addresses,
        settle_timeout):

    token_address = token_addresses[0]

    total_pairs = 0
    pairs = itertools.combinations(raiden_network, 2)
    for app0, app1 in pairs:
        manager = app0.raiden.default_registry.manager_by_token(token_address)
        manager.new_netting_channel(
            app1.raiden.address,
            settle_timeout,
        )
        total_pairs += 1
        assert total_pairs == len(manager.channels_addresses())


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_with_self(raiden_network, settle_timeout, token_addresses):
    app0, = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]

    current_chanels = views.list_channelstate_for_tokennetwork(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )
    assert not current_chanels

    graph0 = app0.raiden.default_registry.manager_by_token(token_address)

    with pytest.raises(SamePeerAddress) as excinfo:
        graph0.new_netting_channel(
            app0.raiden.address,
            settle_timeout,
        )

    assert 'The other peer must not have the same address as the client.' in str(excinfo.value)

    transaction_hash = graph0.proxy.transact(
        'newChannel',
        app0.raiden.address,
        settle_timeout,
    )

    # wait to make sure we get the receipt
    wait_until_block(app0.raiden.chain, app0.raiden.chain.block_number() + 5)
    assert check_transaction_threw(app0.raiden.chain.client, transaction_hash)
