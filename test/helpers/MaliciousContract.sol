// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
// Mock contract to test the Vault's behavior with malicious calls
// Mock malicious contract for testing arbitrary calls

contract MaliciousContract {
    bool public attackPerformed;

    function attack(address vault) external {
        attackPerformed = true;
        // attack can be anything malicious, e.g., toggling emergency stop
        (bool success,) = vault.call(abi.encodeWithSignature("toggleEmergency()"));
        require(success, "Vault call failed");
    }
}
