// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import {IStaking} from "../src/IStaking.sol";
import {MockERC20Token} from "./MockERC20Token.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockStaking is IStaking {
    using SafeERC20 for IERC20;

    IERC20 private token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function collect(uint256 _tokens, address _allocationID) external override {
        // Allocation identifier validation
        require(_allocationID != address(0), "!alloc");

        // Get allocation
        uint256 queryFees = _tokens;

        // Process query fees only if non-zero amount
        if (queryFees > 0) {
            // Pull tokens to collect from the authorized sender
            token.safeTransferFrom(msg.sender, address(this), queryFees);
            // Remainder of staking collect not mocked since it only affects internal state of contract
            // ...
        }
    }
}
