pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import "forge-std/console2.sol";
import {CA_Storage} from "../contracts/CA_Storage.sol";

contract DeployCAStorage is Script {

    function run() external {

        uint256 chainId = block.chainid;
        console2.log("You are deploying on ChainID %d", chainId);

        // Get deployer address
        uint256 deployerKey = uint256(vm.envOr("STORAGE_OWNER_KEY", bytes32(0)));
        vm.startBroadcast(deployerKey);

        // Deploy del contratto CA_Storage
        CA_Storage caStorage = new CA_Storage();
        console2.log("Deployed CA_Storage to", address(caStorage));


        vm.stopBroadcast();
    }
}


