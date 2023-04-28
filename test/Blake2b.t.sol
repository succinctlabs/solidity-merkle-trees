// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/trie/substrate/Blake2b.sol";
import "../src/trie/Bytes.sol";

contract Blake2bTest is Test {
    using Blake2b for Blake2b.Instance;

    function testOneBlock64bytes() public {
        bytes memory digest = Blake2b.blake2b(hex"", 64);
        bytes memory expectedDigest = hex"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
        assertEq0(digest, expectedDigest);
    }

    function testOneBlock32bytes() public {
        bytes memory digest = Blake2b.blake2b(hex"", 32);
        bytes memory expectedDigest = hex"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
        assertEq0(Bytes.substr(digest, 0, 32), expectedDigest);
    }
}
