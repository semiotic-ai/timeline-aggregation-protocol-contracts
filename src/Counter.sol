// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

contract Counter {
    uint256 public number;

    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }

    function increment() public {
        number++;
    }
}
