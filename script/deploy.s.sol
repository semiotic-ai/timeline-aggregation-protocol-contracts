// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.18;

import "forge-std/Script.sol";
import {TAPVerifier} from "../src/TAPVerifier.sol";
import {AllocationIDTracker} from "../src/AllocationIDTracker.sol";
import {Escrow} from "../src/Escrow.sol";



contract TAPDeployScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address tokenAddress = vm.envAddress("TOKEN_ADDRESS");
        address stakingAddress = vm.envAddress("STAKING_ADDRESS");
        uint256 withdrawEscrowThawingPeriod = 30 days;
        uint256 revokeSignerThawingPeriod = 30 days;

        vm.startBroadcast(deployerPrivateKey);

        TAPVerifier tapVerifier = new TAPVerifier("TAP", "1");
        AllocationIDTracker allocationIDTracker = new AllocationIDTracker();
        Escrow escrow = new Escrow(
            tokenAddress,
            stakingAddress,
            address(tapVerifier),
            address(allocationIDTracker),
            withdrawEscrowThawingPeriod,
            revokeSignerThawingPeriod
        );

        vm.stopBroadcast();
    }
}