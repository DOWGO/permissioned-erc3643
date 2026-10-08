// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {OidBytecode} from "./OidBytecode.sol";
import {TrexBytecode} from "./TrexBytecode.sol";

/// @notice The ONCHAINID 2.2.1 `Identity` and `ClaimIssuer` calls the fixtures make.
interface IOnchainId {
    function addKey(bytes32 key, uint256 purpose, uint256 keyType) external returns (bool);
    function addClaim(
        uint256 topic,
        uint256 scheme,
        address issuer,
        bytes calldata signature,
        bytes calldata data,
        string calldata uri
    ) external returns (bytes32);
    function revokeClaimBySignature(bytes calldata signature) external;
}

/// @notice ONCHAINID 2.2.1 `IdentityProxy`.
interface IIdentityProxy {
    function implementationAuthority() external view returns (address);
}

/// @notice T-REX 4.1.6 `TREXImplementationAuthority`.
interface ITrexImplementationAuthority {
    struct TREXContracts {
        address tokenImplementation;
        address ctrImplementation;
        address irImplementation;
        address irsImplementation;
        address tirImplementation;
        address mcImplementation;
    }

    struct Version {
        uint8 major;
        uint8 minor;
        uint8 patch;
    }

    function addAndUseTREXVersion(Version calldata version, TREXContracts calldata trex) external;
}

interface ITrexIdentityRegistry {
    function addAgent(address agent) external;
    function registerIdentity(address user, address identity, uint16 country) external;
    function isVerified(address user) external view returns (bool);
}

interface ITrexIdentityRegistryStorage {
    function bindIdentityRegistry(address identityRegistry) external;
}

interface ITrexClaimTopicsRegistry {
    function addClaimTopic(uint256 topic) external;
}

interface ITrexTrustedIssuersRegistry {
    function addTrustedIssuer(address issuer, uint256[] calldata topics) external;
}

/// @notice Builds the shape the deployer ships, from the published bytecode: ONCHAINID identities
///         behind `IdentityProxy` and its `ImplementationAuthority`, `ClaimIssuer`s deployed directly
///         whose claims are signed by a CLAIM key distinct from the management key, and T-REX
///         registries behind their proxies and `TREXImplementationAuthority`.
abstract contract DeployedShape is Test {
    /// @dev ERC-734 purpose of a key that may sign claims, its ECDSA key type, and the ERC-735
    ///      scheme of an ECDSA claim.
    uint256 internal constant CLAIM_SIGNER_PURPOSE = 3;
    uint256 internal constant ECDSA_KEY_TYPE = 1;
    uint256 internal constant ECDSA_SCHEME = 1;
    bytes internal constant CLAIM_DATA = hex"01";

    /// @dev Required by every suite, so `isVerified` runs T-REX's own verification loop rather than
    ///      answering true for an empty topic set.
    uint256 internal constant ELIGIBILITY_TOPIC = 7;
    uint16 private constant COUNTRY_CODE = 250;

    struct ClaimIssuerFixture {
        address issuer;
        address manager;
        uint256 signingKey;
    }

    struct TrexSuite {
        address identityRegistry;
        address trustedIssuersRegistry;
        ClaimIssuerFixture eligibilityIssuer;
    }

    address private identityAuthority;
    address private trexAuthority;
    uint256 private issuerNonce;

    function _deploy(bytes memory creationCode) internal returns (address deployed) {
        assembly ("memory-safe") {
            deployed := create(0, add(creationCode, 0x20), mload(creationCode))
        }
        require(deployed != address(0), "fixture deployment failed");
    }

    /// @notice A fresh identity behind `IdentityProxy`, whose MANAGEMENT key is `manager`.
    function _newIdentity(address manager) internal returns (address) {
        if (identityAuthority == address(0)) {
            // Deployed as a library, as the deployer does: only the proxies' storage is ever live.
            address implementation =
                _deploy(abi.encodePacked(OidBytecode.identityCreation(), abi.encode(address(this), true)));
            identityAuthority =
                _deploy(abi.encodePacked(OidBytecode.implementationAuthorityCreation(), abi.encode(implementation)));
        }
        return _deploy(abi.encodePacked(OidBytecode.identityProxyCreation(), abi.encode(identityAuthority, manager)));
    }

    /// @notice A `ClaimIssuer` deployed directly, with a CLAIM signing key added by its manager.
    function _newClaimIssuer() internal returns (ClaimIssuerFixture memory fixture) {
        return _newClaimIssuer(0);
    }

    /// @notice A `ClaimIssuer` deployed directly whose signing key stores `purposesBeforeClaim` other
    ///         purposes ahead of CLAIM, the order that costs `keyHasPurpose` the most.
    function _newClaimIssuer(uint256 purposesBeforeClaim) internal returns (ClaimIssuerFixture memory fixture) {
        string memory tag = vm.toString(++issuerNonce);
        fixture.manager = makeAddr(string.concat("issuerManager", tag));
        address signer;
        (signer, fixture.signingKey) = makeAddrAndKey(string.concat("issuerSigner", tag));
        fixture.issuer = _deploy(abi.encodePacked(OidBytecode.claimissuerCreation(), abi.encode(fixture.manager)));
        bytes32 signerKey = keccak256(abi.encode(signer));
        for (uint256 i = 1; i <= purposesBeforeClaim; i++) {
            vm.prank(fixture.manager);
            IOnchainId(fixture.issuer).addKey(signerKey, 100 + i, ECDSA_KEY_TYPE);
        }
        vm.prank(fixture.manager);
        IOnchainId(fixture.issuer).addKey(signerKey, CLAIM_SIGNER_PURPOSE, ECDSA_KEY_TYPE);
    }

    /// @notice The canonical (r, s, v) signature `ClaimIssuer.isClaimValid` accepts for a claim of
    ///         `topic` over CLAIM_DATA held by `identity`.
    function _signClaim(ClaimIssuerFixture memory fixture, address identity, uint256 topic)
        internal
        pure
        returns (bytes memory)
    {
        return _signClaim(fixture, identity, topic, CLAIM_DATA);
    }

    /// @notice The canonical (r, s, v) signature `ClaimIssuer.isClaimValid` accepts for a claim of
    ///         `topic` over `data` held by `identity`.
    function _signClaim(ClaimIssuerFixture memory fixture, address identity, uint256 topic, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 dataHash = keccak256(abi.encode(identity, topic, data));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fixture.signingKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Stores a claim through the identity's own `addClaim`, with an unsigned `uri` of
    ///         `uriLength` zero bytes.
    function _addClaim(
        address identity,
        address manager,
        address issuer,
        uint256 topic,
        bytes memory signature,
        uint256 uriLength
    ) internal {
        _addClaim(identity, manager, issuer, topic, signature, CLAIM_DATA, uriLength);
    }

    /// @notice Stores a claim over `data` through the identity's own `addClaim`, with an unsigned
    ///         `uri` of `uriLength` zero bytes.
    function _addClaim(
        address identity,
        address manager,
        address issuer,
        uint256 topic,
        bytes memory signature,
        bytes memory data,
        uint256 uriLength
    ) internal {
        vm.prank(manager);
        IOnchainId(identity).addClaim(topic, ECDSA_SCHEME, issuer, signature, data, string(new bytes(uriLength)));
    }

    /// @notice A T-REX registry suite requiring ELIGIBILITY_TOPIC, with its own `ClaimIssuer`
    ///         trusted for that topic. All suites share one implementation authority, as a
    ///         deployment's do.
    function _newTrexSuite() internal returns (TrexSuite memory suite) {
        address authority = _trexAuthority();
        address topics =
            _deploy(abi.encodePacked(TrexBytecode.claimTopicsRegistryProxyCreation(), abi.encode(authority)));
        address issuers =
            _deploy(abi.encodePacked(TrexBytecode.trustedIssuersRegistryProxyCreation(), abi.encode(authority)));
        address identities =
            _deploy(abi.encodePacked(TrexBytecode.identityRegistryStorageProxyCreation(), abi.encode(authority)));
        address registry = _deploy(
            abi.encodePacked(
                TrexBytecode.identityRegistryProxyCreation(), abi.encode(authority, issuers, topics, identities)
            )
        );
        ITrexIdentityRegistryStorage(identities).bindIdentityRegistry(registry);
        ITrexIdentityRegistry(registry).addAgent(address(this));
        ITrexClaimTopicsRegistry(topics).addClaimTopic(ELIGIBILITY_TOPIC);

        suite.identityRegistry = registry;
        suite.trustedIssuersRegistry = issuers;
        suite.eligibilityIssuer = _newClaimIssuer();
        _trust(suite, suite.eligibilityIssuer.issuer, ELIGIBILITY_TOPIC);
    }

    /// @notice Gives `identity` an eligibility claim and registers it for `account`, which T-REX's
    ///         own `isVerified` must then accept.
    function _registerVerified(TrexSuite memory suite, address account, address identity, address manager) internal {
        ClaimIssuerFixture memory eligibility = suite.eligibilityIssuer;
        bytes memory signature = _signClaim(eligibility, identity, ELIGIBILITY_TOPIC);
        _addClaim(identity, manager, eligibility.issuer, ELIGIBILITY_TOPIC, signature, 0);
        ITrexIdentityRegistry(suite.identityRegistry).registerIdentity(account, identity, COUNTRY_CODE);
        require(ITrexIdentityRegistry(suite.identityRegistry).isVerified(account), "fixture holder not verified");
    }

    /// @notice Trusts `issuer` for `topic` alone, so it occupies one entry of that topic's list.
    function _trust(TrexSuite memory suite, address issuer, uint256 topic) internal {
        uint256[] memory topics = new uint256[](1);
        topics[0] = topic;
        ITrexTrustedIssuersRegistry(suite.trustedIssuersRegistry).addTrustedIssuer(issuer, topics);
    }

    function _trexAuthority() private returns (address) {
        if (trexAuthority != address(0)) return trexAuthority;
        // A reference authority, as the deployer creates it, with no factory wired.
        trexAuthority = _deploy(
            abi.encodePacked(TrexBytecode.implementationAuthorityCreation(), abi.encode(true, address(0), address(0)))
        );
        // The fixtures deploy no token or compliance proxy; the authority only requires those two
        // slots to be non-zero, so they hold labelled placeholders rather than code.
        ITrexImplementationAuthority.TREXContracts memory implementations = ITrexImplementationAuthority.TREXContracts({
            tokenImplementation: makeAddr("unusedTokenImplementation"),
            ctrImplementation: _deploy(TrexBytecode.claimTopicsRegistryCreation()),
            irImplementation: _deploy(TrexBytecode.identityRegistryCreation()),
            irsImplementation: _deploy(TrexBytecode.identityRegistryStorageCreation()),
            tirImplementation: _deploy(TrexBytecode.trustedIssuersRegistryCreation()),
            mcImplementation: makeAddr("unusedComplianceImplementation")
        });
        ITrexImplementationAuthority(trexAuthority)
            .addAndUseTREXVersion(ITrexImplementationAuthority.Version(4, 1, 6), implementations);
        return trexAuthority;
    }
}
