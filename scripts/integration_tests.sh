#!/bin/bash
# Copyright 2023-, Semiotic AI, Inc.
# SPDX-License-Identifier: Apache-2.0

# Add nvm to sources to use during script
source ~/.nvm/nvm.sh

# Set strict mode for error handling
set -e

# Constants
DEPLOYER=0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1

# Function to handle errors
error_exit() {
    echo "$1" >&2
    exit "${2:-1}"
}

# Function to parse command line arguments
parse_args() {
    # Set defaults
    graph_contracts=lib/contracts
    tap_contracts=./
    RUN_INTEGRATION_TESTS=false

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --graph-contracts)
                graph_contracts="$2"
                shift
                ;;
            --tap-contracts)
                tap_contracts="$2"
                shift
                ;;
            --run-integration-tests)
                export RUN_INTEGRATION_TESTS=true
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
        shift
    done
}

start_node_background() {
    anvil --chain-id '1337' \
          --mnemonic 'myth like bonus scare over problem client lizard pioneer submit female collect' \
          --host '0.0.0.0' \
          --silent \
          &
    local anvil_pid=$!
    echo "anvil node running (PID: $anvil_pid)"
    trap "kill $anvil_pid 2>/dev/null" EXIT INT TERM ERR
}

deploy_graph_contracts() {
    cd "$graph_contracts"
    echo "Starting deploy for The Graph contracts located in $PWD"
    # Hardhat requires an older version of node
    nvm install 16.0.0
    nvm use 16.0.0
    yarn
    yes | yarn deploy-localhost --auto-mine
    export GRAPH_NODE_ADDRESS="$(jq '.["1337"].GraphToken.address' addresses.json | tr -d '"' || error_exit "Error obtaining Graph Node address")"
    export STAKING_ADDRESS="$(jq '.["1337"].L1Staking.address' addresses.json | tr -d '"' || error_exit "Error obtaining Staking address")"
    export CONTROLLER_ADDRESS="$(jq '.["1337"].Controller.address' addresses.json | tr -d '"' || error_exit "Error obtaining Controller address")"
    echo "The Graph contracts deployed, addresses listed in: $PWD/addresses.json"
    cd -
}

deploy_tap_contracts() {
    cd "$tap_contracts"
    echo "Starting deploy for TAP contracts located in $PWD"
    export WITHDRAW_ESCROW_FREEZE_PERIOD=800
    export REVOKE_SIGNER_FREEZE_PERIOD=800
    yarn
    export ALLOCATION_TRACKER_ADDRESS=$(forge create \
        --unlocked --from $DEPLOYER \
        --rpc-url localhost:8545 src/AllocationIDTracker.sol:AllocationIDTracker --json \
        | jq -Rr 'fromjson? | .deployedTo')
    export TAP_VERIFIER_ADDRESS=$(forge create \
        --unlocked --from $DEPLOYER \
        --rpc-url localhost:8545 src/TAPVerifier.sol:TAPVerifier \
        --constructor-args 'tapVerifier' '1.0' --json \
        | jq -Rr 'fromjson? | .deployedTo')
    export ESCROW_ADDRESS=$(forge create \
        --unlocked --from $DEPLOYER \
        --rpc-url localhost:8545 src/Escrow.sol:Escrow \
        --constructor-args $GRAPH_NODE_ADDRESS $STAKING_ADDRESS $TAP_VERIFIER_ADDRESS $ALLOCATION_TRACKER_ADDRESS $WITHDRAW_ESCROW_FREEZE_PERIOD $REVOKE_SIGNER_FREEZE_PERIOD --json \
        | jq -Rr 'fromjson? | .deployedTo')
    echo "TAP contracts deployed"
    cd -
}

main() {
    parse_args "$@"
    start_node_background
    deploy_graph_contracts
    deploy_tap_contracts

    echo "Contracts are deployed."

    if $RUN_INTEGRATION_TESTS; then
        echo "Running integration tests..."
        #run integration tests...
        forge test --match-contract EscrowContractTest --rpc-url localhost:8545
    else
        echo "Node is running on localhost:8545"
        echo "Press ctrl+c to exit"
        while true; do
            sleep 86400  # Sleep for a long time, e.g., one day
        done
    fi
}

main "$@"
