// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// Contract with no receive or fallback function to cause transfer failure
contract NoReceiveContract {
// Intentionally left empty to reject ETH transfers
}
