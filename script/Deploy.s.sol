
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";

import {CA_Storage} from "../contracts/CA_Storage.sol";
import {CfWallet} from "../contracts/CfWallet.sol";

/// @notice Deployment script for the RISC Zero starter project.
/// @dev Use the following environment variable to control the deployment:
///     * Set one of these two environment variables to control the deployment wallet:
///         * ETH_WALLET_PRIVATE_KEY private key of the wallet account.
///         * ETH_WALLET_ADDRESS address of the wallet account.
///
/// See the Foundry documentation for more information about Solidity scripts,
/// including information about wallet options.
///
/// https://book.getfoundry.sh/tutorials/solidity-scripting
/// https://book.getfoundry.sh/reference/forge/forge-script
contract RiscZeroCFWalletDeploy is Script {
    // Path to deployment config file, relative to the project root.
    string constant CONFIG_FILE = "script/config.toml";

    IRiscZeroVerifier verifier;
    bytes cf = hex"41424344454639395032414830303041"; //ABCDEF99P21H000A
    bytes4 salt = 0x01020304;

 
    function run() external {
        // Read and log the chainID
        uint256 chainId = block.chainid;
        console2.log("You are deploying on ChainID %d", chainId);

        // Read the config profile from the environment variable, or use the default for the chainId.
        // Default is the first profile with a matching chainId field.
        string memory config = vm.readFile(string.concat(vm.projectRoot(), "/", CONFIG_FILE));
        string memory configProfile = vm.envOr("CONFIG_PROFILE", string(""));
        if (bytes(configProfile).length == 0) {
            string[] memory profileKeys = vm.parseTomlKeys(config, ".profile");
            for (uint256 i = 0; i < profileKeys.length; i++) {
                if (stdToml.readUint(config, string.concat(".profile.", profileKeys[i], ".chainId")) == chainId) {
                    configProfile = profileKeys[i];
                    break;
                }
            }
        }

        if (bytes(configProfile).length != 0) {
            console2.log("Deploying using config profile:", configProfile);
            string memory configProfileKey = string.concat(".profile.", configProfile);
            address riscZeroVerifierAddress =
                stdToml.readAddress(config, string.concat(configProfileKey, ".riscZeroVerifierAddress"));
            // If set, use the predeployed verifier address found in the config.
            verifier = IRiscZeroVerifier(riscZeroVerifierAddress);
        }

        // Determine the wallet to send transactions from.
        uint256 deployerKey = uint256(vm.envOr("ETH_WALLET_PRIVATE_KEY", bytes32(0)));
        address deployerAddr = address(0);
        if (deployerKey != 0) {
            // Check for conflicts in how the two environment variables are set.
            address envAddr = vm.envOr("ETH_WALLET_ADDRESS", address(0));
            require(
                envAddr == address(0) || envAddr == vm.addr(deployerKey),
                "conflicting settings from ETH_WALLET_PRIVATE_KEY and ETH_WALLET_ADDRESS"
            );

            vm.startBroadcast(deployerKey);
        } else {
            deployerAddr = vm.envAddress("ETH_WALLET_ADDRESS");
            vm.startBroadcast(deployerAddr);
        }

        // Deploy the verifier, if not already deployed.
        if (address(verifier) == address(0)) {
            verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
            console2.log("Deployed RiscZeroGroth16Verifier to", address(verifier));
        } else {
            console2.log("Using IRiscZeroVerifier contract deployed at", address(verifier));
        }

        /*
        // get ca_storage contract address (if exists)
        // if not exists, read DEPLOY_STORAGE env var (contains deployer address)
        address caStorageAddress = stdToml.readAddress(config, ".deployment.CA_Storage");
        if (caStorageAddress == address(0)) {
            // Controlla se DEPLOY_STORAGE è impostata, altrimenti vai in errore (non posso deployare a address == 0)
            address storageDeployerAddr = uint256(vm.envOr("DEPLOY_STORAGE", address(0)));
            if (storageDeployerAddr == address(0)) {
            // ERROR!!! 
            break; //TODO
            }
            // Deploy del contratto CA_Storage
            CA_Storage caStorage = new CA_Storage(storageDeployerAddr);
            console2.log("Deployed CA_Storage to", address(caStorage));

            // Scrivi l'indirizzo di CA_Storage nel file di configurazione
            stdToml.writeAddress(string.concat(vm.projectRoot(), "/", CONFIG_FILE), ".deployment.CA_Storage", address(caStorage));
        } else {
            console2.log("CA_Storage yet deployed at:", caStorageAddress);
        }*/


        //bytes32 saltedCf = keccak256(abi.encodePacked(cf, salt)); //not working, or i missing something




        bytes32 saltedCf = hex"f5b5525190513583b016d16a12c459b6efc94602cdf39c5b190f0368b7266e66"; //value taken from guest code

        address caStorageAddress = vm.envAddress("CA_STORAGE_ADDRESS");
        CfWallet cfwallet = new CfWallet(verifier, caStorageAddress, saltedCf);
        console2.log("Deployed CfWallet to", address(cfwallet));
        console2.log("with saltedCf = ");
        console2.logBytes32(saltedCf);

        vm.stopBroadcast();
    }
}
