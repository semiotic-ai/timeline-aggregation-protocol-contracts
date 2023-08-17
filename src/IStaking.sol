// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @title IStaking
 * @dev This interface is intended to mock the necessary functions of the `Staking` contract while using a
 *      version of solidity consistent with the project.
 * @notice When deploying this interface should be attached to the `Staking` contract.
 */
interface IStaking {
    function collect(uint256 _tokens, address _allocationID) external;
}
