// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {RiscZeroCheats} from "risc0/test/RiscZeroCheats.sol";
import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {CfWallet} from "../CfWallet.sol";
import {CA_Storage} from "../CA_Storage.sol";
import {Elf} from "./Elf.sol"; // auto-generated contract after running `cargo build`.

contract CfWalletTest is RiscZeroCheats, Test {
    CfWallet public cfwallet;
    CA_Storage public ca_storage;
    bytes32 public saltedCf = 0xf5b5525190513583b016d16a12c459b6efc94602cdf39c5b190f0368b7266e66;
    bytes32 public tamperedCf = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdea;

    bytes journal = hex"71c7656ec7ab88b098defb751b7401b5f6d8976ff5b5525190513583b016d16a12c459b6efc94602cdf39c5b190f0368b7266e66b9baeb42d2bec05bacb61ac7eb7cd639f07a84b011fe3875091bbf0427514b8d93d09cf9819bd47b64046ae5993ac12309e78913b4622f8d56c63f80ca7e834c1ad4f82a6d6e9bd5cc19817efe2408ef347e4e844de7b4ef33ef48bca03ea2f36c4f134b66d56c58efea2eb8cba56278f1f963c3fed611ee6159470ba0e55e6a778d52f2cc030dd8439472bb1ecbc55b5d40ff8b1e99de19cbb4954382fcecca147a9d91de759afbe12705cb1c6f2a2af64f17bd60a3036de68afd90ee2af1ac742534f52ebb09ae166c956ecd81a8c00e4a366edf412f01986875e96c5169492691924052f1d06288f97fd6cf2639a151edf63952c9f45cb0b86084d960e9f9";
    bytes seal = hex"50bd17690d0a585c5ce8611fd560bfbce07d7d706e4fb3c975c9c54940836b8dd7b171ac126ba80a6629ceeb0dd56222586cdb09c766a86b76182de0ded06bd276a84e05102a962b7a5713ae0b52149f37e0dd09574401d6098628e7ad25d2f2a8cf26181f0b2aff883557311ffbd676f33e80fd6fa90ac5a7ba32ac4a26915b34696edf24d780af3a6750e6d8f530ec13a00f63e6fe01821d41273cdee65096f35891361efd17f2d0c02773d39ac085a1fce91a1209e6990564e39c97c4302388a1cecb065d7eb7e6150d1885458922736454ebccce491fc0a6afe2260d911e2db2dca122fb4d0a525f1b12c5edf001a53848431400b38da7b09c2afe0f4357da3fe25d";
    bytes seal_tamp = hex"10000000a3f65a942d6400e4c4f9ef51b6eae03954b0e652494d068929fba8fc30314db1";

    bytes myCAkey = hex"b9baeb42d2bec05bacb61ac7eb7cd639f07a84b011fe3875091bbf0427514b8d93d09cf9819bd47b64046ae5993ac12309e78913b4622f8d56c63f80ca7e834c1ad4f82a6d6e9bd5cc19817efe2408ef347e4e844de7b4ef33ef48bca03ea2f36c4f134b66d56c58efea2eb8cba56278f1f963c3fed611ee6159470ba0e55e6a778d52f2cc030dd8439472bb1ecbc55b5d40ff8b1e99de19cbb4954382fcecca147a9d91de759afbe12705cb1c6f2a2af64f17bd60a3036de68afd90ee2af1ac742534f52ebb09ae166c956ecd81a8c00e4a366edf412f01986875e96c5169492691924052f1d06288f97fd6cf2639a151edf63952c9f45cb0b86084d960e9f9";
    bytes realCAkey = hex"30820122300d06092a864886f70d01010105000382010f003082010a0282010100d42c25be1c8f4312511412c7d2801b439d57686c515211f00c48057d46e77297d451ca316fdc3403e86e753962650a44c389b86a0edb1b12495437a1388e3ab338143c48d65ba0b9e848a2dab83c34aec748479c51c9d70e5540106d418ea0d9b5425f2280a497286224ca65753c1209c6feb189913d9ccfacee21c54cbc29df5dccdc23b7b9a7d79485e32ecd34afbbe2c364c92d898cd8f74d90bcb6e81b0a3a79343ba49bd72cf032d49c543900ed21e9d09965017f164aa40d5cc5741fc9a9f3cac846ebe37ac59aa3772abb7a00646a0204959ca1097d8d664d3eee595639de7d3da62fe11fe40c067c2d6568f73a2ce5609c455d7b8ae500437092f4630203010001";
    bytes fakeCAkey = hex"a9baeb42d2bec05bacb61ac7eb7cd639f07a84b011fe3875091bbf0427514b8d93d09cf9819bd47b64046ae5993ac12309e78913b4622f8d56c63f80ca7e834c1ad4f82a6d6e9bd5cc19817efe2408ef347e4e844de7b4ef33ef48bca03ea2f36c4f134b66d56c58efea2eb8cba56278f1f963c3fed611ee6159470ba0e55e6a778d52f2cc030dd8439472bb1ecbc55b5d40ff8b1e99de19cbb4954382fcecca147a9d91de759afbe12705cb1c6f2a2af64f17bd60a3036de68afd90ee2af1ac742534f52ebb09ae166c956ecd81a8c00e4a366edf412f01986875e96c5169492691924052f1d06288f97fd6cf2639a151edf63952c9f45cb0b86084d960e9f9";
    bytes[] CA_key_array = new bytes[](2);
    //CA_key_array[0] = myCAkey;

    //remove verifier.verify from contract to pass all the tests

    function setUp() public {
        IRiscZeroVerifier verifier = deployRiscZeroVerifier();

        //ca_storage = CA_Storage(0x8464135c8F25Da09e49BC8782676a84730C318bC);
        ca_storage = new CA_Storage();
        CA_key_array[0] = myCAkey;
        CA_key_array[1] = realCAkey;
        ca_storage.addPublicKeys(CA_key_array);
        //ca_storage.addPublicKeys(CA_key_array); 
        

        cfwallet = new CfWallet(verifier, address(ca_storage), saltedCf);
        assertEq(cfwallet.get_owner(), saltedCf);
    }



    // test CA_Storage verify function
    function test_verifyPublicKey() public {
        //bytes memory pkreceived = ca_storage.getSomeKeys();
        bool verified = ca_storage.verifyPublicKey(myCAkey);
        assertTrue(verified, "Public key verification failed");

        bool not_verified = ca_storage.verifyPublicKey(fakeCAkey);
        assertTrue(!not_verified, "Fake pub key should not be verified");
    }

    function test_owner() public view {
        bytes32 owner = cfwallet.get_owner();
        assertEq(owner, saltedCf);
        assertEq(saltedCf, 0xf5b5525190513583b016d16a12c459b6efc94602cdf39c5b190f0368b7266e66);
        assertNotEq(owner, tamperedCf);
    }

    function test_extractedData() public {
        cfwallet.verifyAndTransfer(journal,seal);

        address payable to = cfwallet.get_extracted_address();
        assertEq(to, 0x71C7656EC7ab88b098defB751B7401B5f6d8976F);

        //bytes32 extractedCF = cfwallet.get_extracted_cf();
        //assertEq(extractedCF, saltedCf);
    }

    // test CFWallet wrong journal lenghts
    function test_wrongJournal() public {
        vm.expectRevert(bytes("Invalid journal length"));
        //vm.expectRevert();
        cfwallet.verifyAndTransfer(hex"00", hex"00");

        bytes memory tooLongInput = new bytes(310); 
        vm.expectRevert(bytes("Invalid journal length"));
        //vm.expectRevert();

        cfwallet.verifyAndTransfer(tooLongInput, hex"00");
    }

    function test_transferInvoked() public {
        payable(address(cfwallet)).transfer(1 ether);
        assertEq(address(cfwallet).balance, 1 ether, "Wallet not funded");

        uint256 contractBalanceBefore = address(cfwallet).balance;

        cfwallet.verifyAndTransfer(journal, seal);
        uint256 recipientBalance = cfwallet.get_extracted_address().balance;
        uint256 contractBalanceAfter = address(cfwallet).balance;

        assertEq(recipientBalance, contractBalanceBefore);
        assertEq(contractBalanceAfter, 0);

        //journal with wrong value of pk (last byte)
        bytes memory wrong_pk_journal = hex"71c7656ec7ab88b098defb751b7401b5f6d8976ff5b5525190513583b016d16a12c459b6efc94602cdf39c5b190f0368b7266e66b9baeb42d2bec05bacb61ac7eb7cd639f07a84b011fe3875091bbf0427514b8d93d09cf9819bd47b64046ae5993ac12309e78913b4622f8d56c63f80ca7e834c1ad4f82a6d6e9bd5cc19817efe2408ef347e4e844de7b4ef33ef48bca03ea2f36c4f134b66d56c58efea2eb8cba56278f1f963c3fed611ee6159470ba0e55e6a778d52f2cc030dd8439472bb1ecbc55b5d40ff8b1e99de19cbb4954382fcecca147a9d91de759afbe12705cb1c6f2a2af64f17bd60a3036de68afd90ee2af1ac742534f52ebb09ae166c956ecd81a8c00e4a366edf412f01986875e96c5169492691924052f1d06288f97fd6cf2639a151edf63952c9f45cb0b86084d960e9f0";
        bytes memory wrong_cf_journal = hex"71c7656ec7ab88b098defb751b7401b5f6d8976fa5b5525190513583b016d16a12c459b6efc94602cdf39c5b190f0368b7266e66b9baeb42d2bec05bacb61ac7eb7cd639f07a84b011fe3875091bbf0427514b8d93d09cf9819bd47b64046ae5993ac12309e78913b4622f8d56c63f80ca7e834c1ad4f82a6d6e9bd5cc19817efe2408ef347e4e844de7b4ef33ef48bca03ea2f36c4f134b66d56c58efea2eb8cba56278f1f963c3fed611ee6159470ba0e55e6a778d52f2cc030dd8439472bb1ecbc55b5d40ff8b1e99de19cbb4954382fcecca147a9d91de759afbe12705cb1c6f2a2af64f17bd60a3036de68afd90ee2af1ac742534f52ebb09ae166c956ecd81a8c00e4a366edf412f01986875e96c5169492691924052f1d06288f97fd6cf2639a151edf63952c9f45cb0b86084d960e9f0";
        bytes32 wrong_cf = hex"a5b5525190513583b016d16a12c459b6efc94602cdf39c5b190f0368b7266e66";
        bytes memory wrong_pk = hex"b9baeb42d2bec05bacb61ac7eb7cd639f07a84b011fe3875091bbf0427514b8d93d09cf9819bd47b64046ae5993ac12309e78913b4622f8d56c63f80ca7e834c1ad4f82a6d6e9bd5cc19817efe2408ef347e4e844de7b4ef33ef48bca03ea2f36c4f134b66d56c58efea2eb8cba56278f1f963c3fed611ee6159470ba0e55e6a778d52f2cc030dd8439472bb1ecbc55b5d40ff8b1e99de19cbb4954382fcecca147a9d91de759afbe12705cb1c6f2a2af64f17bd60a3036de68afd90ee2af1ac742534f52ebb09ae166c956ecd81a8c00e4a366edf412f01986875e96c5169492691924052f1d06288f97fd6cf2639a151edf63952c9f45cb0b86084d960e9f0";

        vm.expectRevert(abi.encodeWithSelector(CfWallet.InvalidCf.selector, wrong_cf));
        cfwallet.verifyAndTransfer(wrong_cf_journal, seal);


        vm.expectRevert(abi.encodeWithSelector(CfWallet.InvalidRootPublicKey.selector, wrong_pk));
        cfwallet.verifyAndTransfer(wrong_pk_journal, seal);
    }
}
