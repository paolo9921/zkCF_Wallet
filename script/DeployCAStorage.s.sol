pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {CA_Storage} from "../contracts/CA_Storage.sol";

contract DeployCAStorage is Script {

    function run() external {
        // Determina l'indirizzo del deployer
        uint256 deployerKey = uint256(vm.envOr("STORAGE_OWNER_KEY", bytes32(0)));
        vm.startBroadcast(deployerKey);

        // Deploy del contratto CA_Storage
        CA_Storage caStorage = new CA_Storage();
        //console2.log("Deployed CA_Storage to", address(caStorage));


        /*[] memory CA_key_array = new bytes[](1);

        CA_key_array[0] = myCAkey;

        caStorage.addPublicKeys(CA_key_array);*/

        vm.stopBroadcast();
    }
}


