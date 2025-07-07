# MultiVulnerableVault Smart Contract

## Overview

The **MultiVulnerableVault** is a Solidity smart contract designed to demonstrate common smart contract vulnerabilities. It allows users to deposit ETH with a minimum of 1 ETH, enforces a 7-day lock period for withdrawals, and includes an emergency stop mechanism.

> **Warning:**  
> This contract contains critical security vulnerabilities and is **not safe for production use**.  
> Refer to the [Security Audit Report](#security-audit) for details.

## Features

- Deposit ETH with a minimum of 1 ETH.
- Withdraw funds after a 7-day lock period.
- Emergency stop functionality to pause deposits and withdrawals (**currently insecure**).
- Whitelisting mechanism for users (**flawed implementation**).
- Owner administration functions (**centralized and vulnerable**).

## Prerequisites

- [Foundry](https://book.getfoundry.sh/) for compiling, testing, and deploying the contract.
- Solidity compiler version `>=0.8.17`  
  _(Note: The current version has known issues; see the audit report.)_

## Installation

Clone the repository:
```bash
git clone github.com/rocknwa/MultiVulnerableVault
cd MultiVulnerableVault
```

Install Foundry dependencies:
```bash
forge install
```

Compile the contract:
```bash
forge build
```

## Testing

Run the test suite to verify contract behavior and vulnerabilities:
```bash
forge test
```

The test suite (`MultiVulnerableVaultTest.sol`) covers critical issues, including:

- Owner fund drainage
- Signature replay attacks
- Unrestricted emergency stop toggling
- State changes on failed withdrawals

See [`test/MultiVulnerableVaultTest.sol`](test/MultiVulnerableVaultTest.sol) for detailed test cases.

## Security Audit

> **Critical Warning:**  
> This contract is intentionally vulnerable and should **not** be deployed on mainnet or used with real funds.

A comprehensive security audit report ([AUDIT.md](security-audit.md)) identifies the following high-severity issues:

- **Owner can drain funds** via `adminWithdraw`
- **Signature replay attacks** in `recoverFunds` allow unauthorized fund drainage
- **Unrestricted emergency stop** enables denial-of-service attacks
- **Arbitrary call execution** in `voteAndExecute` risks malicious actions
- **Non-reverting transfer failures** in `withdraw` cause fund loss
- **Outdated compiler** (`0.8.17`) introduces deployment and security risks

Review the [audit report](docs/AUDIT.md) for a complete list of vulnerabilities and recommended mitigations.

## Contributing

Contributions to improve the contract’s security or documentation are welcome.