// test/ca_storage.t.sol
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {CA_Storage} from "../CA_Storage.sol";

contract CA_StorageTest is Test {
    
    CA_Storage public ca_storage;    

    address testOwner = address(0xDEADBEEF);

    bytes[] public pubKeysTest;

    function setUp() public {
        vm.prank(testOwner);
        ca_storage = new CA_Storage();

        pubKeysTest.push(hex"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        pubKeysTest.push(hex"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        pubKeysTest.push(hex"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
        pubKeysTest.push(hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        pubKeysTest.push(hex"1111111111111111111111111111111111111111111111111111111111111111");
        pubKeysTest.push(hex"2222222222222222222222222222222222222222222222222222222222222222");
    }

    function testAddPublicKeys() public {
        // set owner of contract
        vm.prank(testOwner);
        ca_storage.addPublicKeys(pubKeysTest);

        // Verifica che il contatore sia incrementato correttamente
        assertEq(ca_storage.publicKeyCount(), pubKeysTest.length, "publicKeyCount dovrebbe essere uguale al numero di chiavi aggiunte");

    }

    function testPreventDuplicatePublicKeys() public {
        // Try to add 2 times same key
        vm.prank(testOwner);
        ca_storage.addPublicKeys(pubKeysTest);

        vm.prank(testOwner);
        ca_storage.addPublicKeys(pubKeysTest);

        assertEq(ca_storage.publicKeyCount(), pubKeysTest.length, "publicKeyCount dovrebbe rimanere invariato dopo tentativi di duplicazione");

    }

    function testIsPublicKeyExists() public {
        // Aggiungi le chiavi pubbliche
        vm.prank(testOwner);
        ca_storage.addPublicKeys(pubKeysTest);

        // Verifica l'inesistenza di una chiave non aggiunta tramite KeyChecker
        bytes memory nonExistentKey = hex"afffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        bool exists_false = ca_storage.verifyPublicKey(nonExistentKey);
        assertFalse(exists_false, "Should not be present in mapping");
    }

    function testOnlyOwnerCanAddPublicKeys() public {
        address nonOwner = address(0x123);
        vm.deal(nonOwner, 1 ether); 

        // Prova ad aggiungere chiavi pubbliche da un account non proprietario
        vm.prank(nonOwner);
        vm.expectRevert("Ownership Assertion: Caller is not the owner");
        ca_storage.addPublicKeys(pubKeysTest);
    }


    

}
