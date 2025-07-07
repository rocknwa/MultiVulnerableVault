// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// Helper contract with a receive function for deposit phase
contract ReceiveContract {
    receive() external payable { }
}
