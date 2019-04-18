pragma solidity ^0.5.4;

contract RpcWithStorageTest {
    uint256[] data;

    event RpcEvent(
        uint _someNumber
    );

    function get(uint256 _someId) public returns (uint256) {
        return data[_someId];
    }

    function const() public returns (uint256) {
        return 1;
    }

    function waste_storage(uint256 length, uint256 value) public {
        uint256 i;
        data.length = length;
        for (i=0; i<length; i++) {
            data[i] = value;
        }
        emit RpcEvent(i);
    }
}
