// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
//@audit ^0.8.17 contains known severe issues:
// - VerbatimInvalidDeduplication
// - FullInlinerNonExpressionSplitArgumentEvaluationOrder
// - MissingSideEffectsOnSelectorAccess.
//Solc compiler version 0.8.20 switches the default target EVM version to Shanghai, which means that the generated
// bytecode will include PUSH0 opcodes. Be sure to select the appropriate EVM version in case you intend to deploy on a
// chain other than mainnet like L2 chains that may not support PUSH0, otherwise deployment of your contracts will fail.

contract MultiVulnerableVault {
    struct User {
        uint256 balance;
        uint256 lastDepositTime;
        bool isWhitelisted;
    }

    mapping(address => User) public users;
    address[] public userAddresses;
    //@audit should be immutable
    address public owner;
    bool public emergencyStop;
    uint256 public totalLocked;

    uint256 public constant MAX_USERS = 100;
    uint256 public constant MIN_DEPOSIT = 1 ether;
    uint256 public constant LOCK_PERIOD = 7 days;

    modifier onlyOwner() {
        //@audit use custom errors
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier notEmergency() {
        //@audit use custom errors
        require(!emergencyStop, "Emergency stop activated");
        _;
    }

    constructor() {
        owner = msg.sender;
        emergencyStop = false;
    }

    function deposit() external payable notEmergency {
        //@audit use custom error to optmize gas
        require(msg.value >= MIN_DEPOSIT, "Deposit too small");
        //@audit replace array with counter
        //@audit DOS!
        //@audit once it reaches max, even whitelisted users can't deposit. use a different function for whitelisting
        // function and use this for whitelisted addresses to always deposit
        require(userAddresses.length < MAX_USERS, "Max users reached");

        User storage user = users[msg.sender];

        //@audit  checking balance == 0 instead of isWhitelisted, leading to incorrect re-whitelisting after
        // withdrawals.
        if (user.balance == 0) {
            user.isWhitelisted = true;
            userAddresses.push(msg.sender);
        }

        user.balance += msg.value;
        user.lastDepositTime = block.timestamp;
        totalLocked += msg.value;
        //@audit External call to sender with 0 value (dangerous, can trigger fallback)
        //call not  neccessary
        (bool success,) = msg.sender.call{ value: 0 }("");
        require(success, "Callback failed");
    }
    //@audit  Consider using reentrancy guards.

    function withdraw(uint256 amount) external notEmergency {
        User storage user = users[msg.sender];
        //@audit use custom error to optmize gas
        require(user.balance >= amount, "Insufficient balance");
        require(block.timestamp >= user.lastDepositTime + LOCK_PERIOD, "Funds locked");

        user.balance -= amount;
        totalLocked -= amount;

        (bool sent,) = msg.sender.call{ value: amount }("");
        if (!sent) {
            //@audit should revert, emitting event if transfer fails no state change. This is malicious and can lead to
            // loss of funds.
            emit TransferFailed(msg.sender, amount);
        }
    }
    //@audit : Owner can drain vault.
    //@audit centralization and security risk

    function adminWithdraw(address target, uint256 amount) external onlyOwner {
        (bool sent,) = target.call{ value: amount }("");
        require(sent, "Transfer failed");
    }
    //@audit Anybody can toggle emergency stop, which is a security risk.
    // This function should be restricted to the owner only.
    //@audit The emergency stop can be toggled, which could lead to unexpected behavior.
    //@audit use openzeppelin pausable with access control

    function toggleEmergency() external {
        emergencyStop = !emergencyStop;
    }
    //@audit The voteAndExecute function allows the owner to execute arbitrary calls, which could be dangerous.
    //@audit : The voteAndExecute function allows the owner to execute arbitrary calls, which could be dangerous.
    //@audit : This function can be used to execute malicious code if the owner is compromised.
    //@audit : No voting, owner executes arbitrary calls.
    //@audit Remove or implement multi-sig voting

    function voteAndExecute(address[] memory targets, bytes[] memory data) external onlyOwner {
        require(targets.length == data.length, "Invalid input");
        //@audit Avoid `require` / `revert` statements in a loop because a single bad item can cause the whole
        // transaction to fail. It's better to forgive on fail and return failed elements post processing of the loop
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call(data[i]);
            require(success, "Call failed");
        }
    }
    //@audit sends eth to arbitrary user
    //@audit Signature replay, owner funds theft.
    //@audit : This function allows anyone to recover funds if they have a valid signature from the owner.
    //@audit : The signature is hard-coded, making it easy to replay.
    //@audit : The owner can be tricked into signing a message that allows funds recovery.

    function recoverFunds(bytes memory signature) external {
        bytes32 message = keccak256(abi.encodePacked("RECOVER"));
        address signer = _recoverSigner(message, signature);

        if (signer == owner) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    //@audit Instead of marking a function as `public`, consider marking it as `external` if it is not used internally.
    //@audit Solidity's integer division truncates. Thus, performing division before multiplication can lead to
    // precision loss.
    //@audit In general, it's usually a good idea to re-arrange arithmetic to perform multiplication before division,
    // unless the limit of a smaller type makes this dangerous.
    //@audit  No reward mechanism implemented in the contract; which reward is  this function calculating? Remove
    // function or implement reward being calculated

    function calculateReward(uint256 amount, uint256 periods) public pure returns (uint256) {
        //@audit no magic  numbers
        uint256 reward = amount / 1000;
        return reward * periods;
    }
    //@audit Index event fields make the field more quickly accessible to off-chain tools that parse events.

    event TransferFailed(address indexed user, uint256 amount);
    //@audit The `ecrecover` function is susceptible to signature malleability. This means that the same message can be
    // signed in multiple ways, allowing an attacker to change the message signature without invalidating it. This can
    // lead to unexpected behavior in smart contracts, such as the loss of funds or the ability to bypass access
    // control. Consider using OpenZeppelin's ECDSA library instead of the built-in function.

    function _recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = _splitSignature(sig);
        return ecrecover(message, v, r, s);
    }

    //@audit The use of assembly is error-prone and should be avoided.
    //@audit Recommendation Do not use evm assembly
    function _splitSignature(bytes memory sig) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "Invalid signature");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }
}
