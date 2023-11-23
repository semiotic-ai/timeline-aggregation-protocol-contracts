// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import {IStaking} from "../src/IStaking.sol";
import {MockERC20Token} from "./MockERC20Token.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockStaking is IStaking {
    using SafeERC20 for IERC20;

    IERC20 private token;
    bool private paused;

    mapping (address => Allocation) private allocations;

    mapping (address => bool) private _assetHolders;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // add this to be excluded from coverage report
    function test() public {}

    function allocate(
        bytes32 _subgraphDeploymentID,
        uint256 _tokens,
        address _allocationID,
        bytes32 _metadata,
        bytes calldata _proof
    ) external {
        // Not a real proof validation, just mocking to remove warnings
        if(_proof.length > 0) {
            allocations[_allocationID] =
                Allocation(
                    msg.sender,
                    _subgraphDeploymentID,
                    _tokens,
                    _allocationID,
                    _metadata
                );
        }
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

    function getAllocation(address _allocationID)
        external
        view
        override
        returns (Allocation memory)
    {
        return allocations[_allocationID];
    }

    function stake(uint256 _tokens) external override {
        // Pull tokens to stake from the authorized sender
        token.safeTransferFrom(msg.sender, address(this), _tokens);
    }

    function setAssetHolder(address _assetHolder, bool _allowed)external override {
        _assetHolders[_assetHolder] = _allowed;
    }
}
