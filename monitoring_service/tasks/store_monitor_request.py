import gevent
import logging
from hexbytes import HexBytes
from raiden_libs.messages import MonitorRequest
from raiden_libs.utils.signing import eth_verify
from eth_utils import decode_hex, is_same_address

log = logging.getLogger(__name__)


class StoreMonitorRequest(gevent.Greenlet):
    """Validate & store submitted monitor request. This consists of:
            - check of bp & reward proof signature
            - check if contracts contain code
            - check if there's enough tokens for the payout
        Return:
            True if monitor request is valid
    """
    def __init__(self, web3, state_db, monitor_request):
        super().__init__()
        assert isinstance(monitor_request, MonitorRequest)
        self.msg = monitor_request
        self.state_db = state_db
        self.web3 = web3

    def _run(self):
        checks = [
            self.check_signatures,
            self.verify_contract_code,
            self.check_balance
        ]
        results = [
            check(self.msg)
            for check in checks
        ]
        if not (False in results):
            serialized_bp = self.msg.serialize_data()
            self.state_db.store_monitor_request(serialized_bp)
        return not (False in results)

    def verify_contract_code(self, monitor_request):
        return self.web3.eth.getCode(monitor_request.token_network_address) != HexBytes('0x')

    def check_signatures(self, monitor_request):
        bp = monitor_request.get_balance_proof()
        balance_proof_signer = eth_verify(decode_hex(bp.signature), bp.serialize_bin()) # flake8: noqa
        reward_proof_signer = eth_verify(
            decode_hex(monitor_request.reward_proof_signature),
            monitor_request.serialize_reward_proof()
        )
        return is_same_address(reward_proof_signer, monitor_request.reward_sender_address)

    def check_balance(self, monitor_request):
        return True
