import random

import pytest
from gevent.pool import Pool
from gevent.queue import Queue

from raiden.constants import GAS_SSTORE_COST_FROM_ZERO, GAS_TRANSACTION_INTRINSIC, INT64_MAX
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.tests.integration.rpc.test_assumptions import get_test_contract

pytestmark = pytest.mark.usefixtures('skip_if_not_geth')

# set very low values to force the client to prune old state
STATE_PRUNNING = {
    'cache': 1,
    'trie-cache-gens': 1,
}


def send_transaction(client: JSONRPCClient, proxy: ContractProxy, iterations=1000) -> str:
    block = client.get_block('latest')
    gas_limit = block['gasLimit']
    max_iterations = (gas_limit - GAS_TRANSACTION_INTRINSIC) // GAS_SSTORE_COST_FROM_ZERO
    iterations = random.randint(
        iterations,
        max_iterations // 2,
    )
    value = random.randint(0, INT64_MAX)
    startgas = int(gas_limit * 0.8)
    return proxy.transact('waste_storage', startgas, iterations, value)


def loop_send_transactions(
        client: JSONRPCClient,
        proxy: ContractProxy,
        queue_transactions: Queue,
) -> None:
    while True:
        transaction_hash = send_transaction(client, proxy)
        queue_transactions.put(transaction_hash, block=True, timeout=None)


def collect_receipts(
        client: JSONRPCClient,
        from_queue: Queue,
        to_queue: Queue,
) -> None:
    while True:
        transaction_hash = from_queue.get()
        client.poll(transaction_hash)
        receipt = client.get_transaction_receipt(transaction_hash)
        to_queue.put(receipt)


@pytest.mark.parametrize('number_of_nodes', [10])
@pytest.mark.parametrize('chain_initial_gas_limit', [100000000])
@pytest.mark.parametrize('blockchain_extra_config', [STATE_PRUNNING])
def test_geth_request_prunned_data_raises_an_exception(deploy_client, private_keys, web3):
    """ Interacting with an old block identifier with a pruning client throws. """
    number_of_concurrent_transactions = 2

    contract_path, contracts = get_test_contract(f'RpcWithStorageTest.sol')
    contract_interface = contracts['RpcWithStorageTest.sol:RpcWithStorageTest']['abi']
    contract_proxy, _ = deploy_client.deploy_solidity_contract(
        'RpcWithStorageTest',
        contracts,
        libraries=dict(),
        constructor_parameters=None,
        contract_path=contract_path,
    )
    contract_address = contract_proxy.contract_address

    transaction_hash = send_transaction(
        deploy_client,
        contract_proxy,
    )
    deploy_client.poll(transaction_hash)
    first_receipt = deploy_client.get_transaction_receipt(transaction_hash)
    pruned_block_number = first_receipt['blockNumber']

    pool = Pool()
    queue_receipts = Queue()

    for key in private_keys:
        client = JSONRPCClient(web3, key)
        proxy = client.new_contract_proxy(
            contract_interface,
            contract_address,
        )
        queue_transactions_hashes = Queue(
            maxsize=number_of_concurrent_transactions - 1,
        )

        pool.spawn(
            loop_send_transactions,
            client=client,
            proxy=proxy,
            queue_transactions=queue_transactions_hashes,
        )
        pool.spawn(
            collect_receipts,
            client=client,
            from_queue=queue_transactions_hashes,
            to_queue=queue_receipts,
        )

    while True:
        receipt = queue_receipts.get()
        print(receipt)

        result = proxy.contract.functions.const().call(
            block_identifier=pruned_block_number,
        )
        if result != 1:
            return

        result = proxy.contract.functions.get(1).call(
            block_identifier=pruned_block_number,
        )
        if result != 1:
            return

    with pytest.raises(ValueError):
        contract_proxy.contract.functions.const().call(block_identifier=pruned_block_number)

    with pytest.raises(ValueError):
        contract_proxy.contract.functions.get(1).call(block_identifier=pruned_block_number)
