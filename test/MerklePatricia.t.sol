// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "../src/MerklePatricia.sol";
import "../src/trie/substrate/SubstrateTrieDB.sol";
import "../src/trie/substrate/ScaleCodec.sol";
import "../src/trie/NibbleSlice.sol";

contract MerklePatriciaTest is Test {
    function testSubstrateMerklePatricia() public view {
        bytes[] memory keys = new bytes[](1);
        // trie key for pallet_timestamp::Now
        keys[0] = hex"f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb";

        bytes[] memory proof = new bytes[](2);
        proof[0] =
            hex"802e98809b03c6ae83e3b70aa89acfe0947b3a18b5d35569662335df7127ab8fcb88c88780e5d1b21c5ecc2891e3467f6273f27ce2e73a292d6b8306197edfa97b3d965bd080c51e5f53a03d92ea8b2792218f152da738b9340c6eeb08581145825348bbdba480ad103a9320581c7747895a01d79d2fa5f103c4b83c5af10b0a13bc1749749523806eea23c0854ced8445a3338833e2401753fdcfadb3b56277f8f1af4004f73719806d990657a5b5c3c97b8a917d9f153cafc463acd90592f881bc071d6ba64e90b380346031472f91f7c44631224cb5e61fb29d530a9fafd5253551cbf43b7e97e79a";
        proof[1] =
            hex"9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb2035e90c7f86010000";

        bytes32 root = hex"6b5710000eccbd59b6351fc2eb53ff2c1df8e0f816f7186ddd309ca85e8798dd";
        bytes memory value = MerklePatricia.VerifySubstrateProof(root, proof, keys)[0];
        uint256 timestamp = ScaleCodec.decodeUint256(value);
        assert(timestamp == 1677168798005);
    }

    function testSubstrateMerklePatriciaSingleNode() public {
        bytes[] memory keys = new bytes[](1);
        keys[0] = hex"00";

        bytes[] memory proof = new bytes[](1);
        proof[0] =
        hex"8100110034402c280401000b5db899138701804f1dc18c0729c67df638dcb17ff86372be663d0d85339a845510498c6c42fc3b";

        bytes32 root = hex"9ec7b55dd538898d95dec220abf8f60e8c626bdb4a348d117d1ecaa564cb565c";
        bytes memory value = MerklePatricia.VerifySubstrateProof(root, proof, keys)[0];
        assertEq(ScaleCodec.decodeUintCompact(ByteSlice(value, 4)), 1679661054045);
    }

    function testSubstrateMerklePatriciaEventIndex() public {
        bytes[] memory keys = new bytes[](1);
        // trie key for pallet_Babe::EpochIndex
        keys[0] = hex"1cb6f36e027abb2091cfb5110ab5087f38316cbf8fa0da822a20ac1c55bf1be3";

        bytes[] memory proof = new bytes[](3);
        proof[0] =
        hex"8000148065a1214a991ac85d93f38385d6f52af7b4ddcf56e589fcb92c8d9e8f27291c9280ee666acec9fb8cd7365177fe208a2cf6fba23782ab0fb5854d51c1e1ad0fe218";
        proof[1] =
        hex"9eb6f36e027abb2091cfb5110ab5087ff96c685f06155b3cd9a8c9e5e9a23fd5dc13a5ed20f2aa020500000000685f08316cbf8fa0da822a20ac1c55bf1be320880c000000000000505f0e7b9012096b41c4eb3aaf947f6ea42908000080188a2eb879c7954afd781373437adb2bf42bf57f5ca6db151a9d7024de0ea2488020ce287f9ce3d5a528c407430571d6c65130948d4f7db27a7130d1bfc093b824803181543408d4f9a8f228228d2fd281b6cbe08b32aea8625efc3700705c1ae14b80426238e6604289bc2dcd2550dc75dace3baf52f20fc22831c3684b8684bafb4b80b197254013251373510c7d8dc69a553f44cbb025dc605d549db7b6c58c75f61e80ce174de7a74d4b6d335d2af315296c56df41081ed69bb49cca293d94853024e3685f090e2fbf2d792cb324bffa9427fe1f0e2037cc0800d8cc0800";
        proof[2] =
        hex"80eef780628206558dfb36849be6688f8d81bbf107d636b3204d7b9b4436c9db5091815e8063dc3e4db7f195838c007ad0f5069c6cc028025442555f1207c9a3364cc438c480700a088ddf7f878238871f0bbcb3a696ca746438a964ef14c8718f1cdcb8fb52809c6b07d10ceee871fde9d14503d41229ce7c1be8bb1797d2280efcf2b25fe10280bfaff3153a942398e2ff81bf4d68dd479204b4f0e40c2080a1568c608625360f80c55e6794db9f6aef3917f5b0da28ff18d812e5627b62989d6272491bfdbbc27f804a7d38fe753184553cd50f55f5fb73b60c7bf124b0921aa1065743dcf001d39a80cb506a4862eaf26452f49c62a348bfdb41c56c1e52e351f097fd91208fb11e7f80a8e512184f16536b886d917e281233552da74d559df8f3417ea48b69115d0a798065a9cef34d5987b34228efa18b3ce9ceeb93b8013fe0c6a1db6b9cb2530e8cfc80d476a007da708aeef421d3eecbe43bf84a0d7d290accb5b6ef94d801614bede980be5ed71a519ac2d3e0b7f16ff99f12aa76de574a4b0a65c08ef664e88393d25580731a4dedef40700bbe3fb131a481f9ec97fd2ab2cb3897b3a0ac78eebfad3744";

        bytes32 root = hex"110769b4c5b850bd3b8276b39daf6dece324cef62e214c3768a7a12da7a8ff7c";
        bytes memory value = MerklePatricia.VerifySubstrateProof(root, proof, keys)[0];
        assertEq(ScaleCodec.decodeUint64(value), 3208);
    }

    function testSubstrateMerklePatriciaEvents() public {
        bytes[] memory keys = new bytes[](1);
        // trie key for System::Events
        keys[0] = hex"26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7";

        bytes[] memory proof = new bytes[](5);
        proof[0] =
        hex"80419880cc78e4737245c6f39359217eadc3c743ac5eda3e7d35b6640aef7ef22c99e68c80137280390ac8adba85d29aa7eb0837d404342ace92f4ea9bf9598d6a5d081e998074dbd614545401866dab14cb90a2eb7d852d80f677540b2098d7411a22dc6dec80e1516a1a4eb4cb87b3646638e981c48bd767cea4818038661c55eaa0358f40658046c631a36544e1f5ff4555630db0d07b100c137712529dcc2f04bfef51b7f9bd";
        proof[1] =
        hex"5ed41e5e16056765bc8461851072c9d70d0b240214020454565c44d9561b54219d44200551ab30df36bbca0cd777991868e09344c70f751b958da3cce7cc04026701178e7d642d2d1b8b513604a4ce65677bdad5df37463a583b2c0cd86f2d9ba097d5e3340c2e0c0f57f5ff111b07103f9fbab179b0300100020a0a54565c44d9561b54219d44200551ab30df36bbca0cd777991868e09344c70f7500021600696d2d6f6e6c696e653a6f66666c696e10870c000000020a0017020000c549f41bd5376aa607000000000000008e4efcb6c70314531600000000000000000206076d6f646c70792f747273727900000000000000000000000000000000000000008e4efcb6c70314531600000000000000000212068e4efcb6c7031453160000000000000000020b00880c00000000000000000000585f8f0900000000020000011100280c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c5501000000000000008d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b60100000000000000e1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b240100000000000000cc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced0100000000000000e4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a79701000000000000002ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb786000100000000000000079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb20100000000000000335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e430100000000000000d4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec0100000000000000483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097010000000000000000";
        proof[2] =
        hex"80eef780628206558dfb36849be6688f8d81bbf107d636b3204d7b9b4436c9db5091815e8063dc3e4db7f195838c007ad0f5069c6cc028025442555f1207c9a3364cc438c480700a088ddf7f878238871f0bbcb3a696ca746438a964ef14c8718f1cdcb8fb52809c6b07d10ceee871fde9d14503d41229ce7c1be8bb1797d2280efcf2b25fe10280bfaff3153a942398e2ff81bf4d68dd479204b4f0e40c2080a1568c608625360f80c55e6794db9f6aef3917f5b0da28ff18d812e5627b62989d6272491bfdbbc27f804a7d38fe753184553cd50f55f5fb73b60c7bf124b0921aa1065743dcf001d39a80cb506a4862eaf26452f49c62a348bfdb41c56c1e52e351f097fd91208fb11e7f80a8e512184f16536b886d917e281233552da74d559df8f3417ea48b69115d0a798065a9cef34d5987b34228efa18b3ce9ceeb93b8013fe0c6a1db6b9cb2530e8cfc80d476a007da708aeef421d3eecbe43bf84a0d7d290accb5b6ef94d801614bede980be5ed71a519ac2d3e0b7f16ff99f12aa76de574a4b0a65c08ef664e88393d25580731a4dedef40700bbe3fb131a481f9ec97fd2ab2cb3897b3a0ac78eebfad3744";
        proof[3] =
        hex"9eaa394eea5630e07c48ae0c9558cef7398f80dbf0402002c306cc458da3da4cdd578c02905de29b1fc72d13b9b873a3abce07809df2a9fe70ade470aec5da13064ed1505ac0542a0edde5be3714971e13a7feee505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f0684a022a34dd8bfa2baaf44f172b710040180c4c5b828473aab675b71cbc2e2a6ce92c95d85289102f8871eaf527dc693a76e80d51576176d60e3c333f0d7ef97001fe3914f1d4c85c0cd6e5735a3c95479457980dd9f156fe9f6a4575e83b2d1aa350eb390d0ac4042ae7954ea8a29e6cb613ec280601f5243967037d339640d418016cf43c63e2b8991c804d1413146b1a1b8e826785f09cce9c888469bb1a0dceaa129672ef8301828646174612d617661696c";
        proof[4] =
        hex"800104805373371b8a7c9c7bef6d6f29040f6004b027f0eae598921fe07dbb96a0208c71804a5a9ddc56f43007ec0d48cf80d3b0978362ae7bbdbe6121e47cbeae03152c1d";

        bytes32 root = hex"110769b4c5b850bd3b8276b39daf6dece324cef62e214c3768a7a12da7a8ff7c";
        bytes memory value = MerklePatricia.VerifySubstrateProof(root, proof, keys)[0];
        bytes memory expectedByteValue = hex"240214020454565c44d9561b54219d44200551ab30df36bbca0cd777991868e09344c70f751b958da3cce7cc04026701178e7d642d2d1b8b513604a4ce65677bdad5df37463a583b2c0cd86f2d9ba097d5e3340c2e0c0f57f5ff111b07103f9fbab179b0300100020a0a54565c44d9561b54219d44200551ab30df36bbca0cd777991868e09344c70f7500021600696d2d6f6e6c696e653a6f66666c696e10870c000000020a0017020000c549f41bd5376aa607000000000000008e4efcb6c70314531600000000000000000206076d6f646c70792f747273727900000000000000000000000000000000000000008e4efcb6c70314531600000000000000000212068e4efcb6c7031453160000000000000000020b00880c00000000000000000000585f8f0900000000020000011100280c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c5501000000000000008d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b60100000000000000e1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b240100000000000000cc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced0100000000000000e4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a79701000000000000002ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb786000100000000000000079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb20100000000000000335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e430100000000000000d4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec0100000000000000483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097010000000000000000";

        assertEq0(value, expectedByteValue);

        // Todo:  Scale decode the byte value
    }

    function VerifyKeys(bytes32 root, bytes[] memory proof, bytes[] memory keys) public view returns (bytes[] memory) {
        return MerklePatricia.VerifySubstrateProof(root, proof, keys);
    }

    function decodeNodeKind(bytes memory node) public pure returns (NodeKind memory) {
        return SubstrateTrieDB.decodeNodeKind(node);
    }

    function decodeNibbledBranch(bytes memory node) external pure returns (NibbledBranch memory) {
        return SubstrateTrieDB.decodeNibbledBranch(SubstrateTrieDB.decodeNodeKind(node));
    }

    function decodeLeaf(bytes memory node) external pure returns (Leaf memory) {
        return SubstrateTrieDB.decodeLeaf(SubstrateTrieDB.decodeNodeKind(node));
    }

    function nibbleLen(NibbleSlice memory nibble) public pure returns (uint256) {
        return NibbleSliceOps.len(nibble);
    }

    function mid(NibbleSlice memory self, uint256 i) public pure returns (NibbleSlice memory) {
        return NibbleSliceOps.mid(self, i);
    }

    function isNibbleEmpty(NibbleSlice memory self) public pure returns (bool) {
        return NibbleSliceOps.isEmpty(self);
    }

    function eq(NibbleSlice memory self, NibbleSlice memory other) public pure returns (bool) {
        return NibbleSliceOps.eq(self, other);
    }

    function nibbleAt(NibbleSlice memory self, uint256 i) public pure returns (uint256) {
        return NibbleSliceOps.at(self, i);
    }

    function startsWith(NibbleSlice memory self, NibbleSlice memory other) public pure returns (bool) {
        return NibbleSliceOps.startsWith(self, other);
    }

    function commonPrefix(NibbleSlice memory self, NibbleSlice memory other) public pure returns (uint256) {
        return NibbleSliceOps.commonPrefix(self, other);
    }
}
