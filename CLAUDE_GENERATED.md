# Claude Generated Code

**Task**: Objective: Help design and implement new features based on the current roadmap or project needs. Focus on clean, scalable, and testable code  Claude Tasks:  🧩 Feature Implementation Read the existing codebase and integrate new feature modules where appropriate.  Ensure new code follows existing patterns and conventions.  🗂️ Example Features (replace/add specifics as needed): Add user role-based access control  Implement export to PDF  Add multi-language support  Enable dark mode toggle  🧪 Testing & Documentation Add unit/integration tests for new functionality.  Update README or in-code comments if required.

**Generated on**: Thu Jul 31 06:20:35 UTC 2025

## Generated Content

```
Looking at the current codebase, I can see this is a Filecoin onramp project that helps developers write data to the Filecoin network. Based on the roadmap needs, I'll implement a comprehensive **Role-Based Access Control (RBAC)** system that integrates cleanly with the existing contracts.

## FILES_TO_CREATE

1. `src/AccessControl.sol` - Core RBAC contract
2. `src/interfaces/IAccessControl.sol` - Interface for RBAC functionality
3. `test/AccessControl.t.sol` - Comprehensive tests for RBAC
4. `test/OnRampAccessControl.t.sol` - Integration tests

## FILES_TO_MODIFY

1. `src/OnRamp.sol` - Add RBAC integration
2. `src/Prover.sol` - Add RBAC integration
3. `src/Oracles.sol` - Add RBAC integration

## CODE_CHANGES

### NEW FILES

**FILES_TO_CREATE: `src/interfaces/IAccessControl.sol`**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title IAccessControl
 * @dev Interface for role-based access control system
 * @notice Provides functionality for managing roles and permissions
 */
interface IAccessControl {
    /**
     * @dev Emitted when a role is granted to an account
     * @param role The role identifier
     * @param account The account receiving the role
     * @param sender The account granting the role
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when a role is revoked from an account
     * @param role The role identifier
     * @param account The account losing the role
     * @param sender The account revoking the role
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when a role's admin role is changed
     * @param role The role identifier
     * @param previousAdminRole The previous admin role
     * @param newAdminRole The new admin role
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Returns true if account has been granted role
     * @param role The role to check
     * @param account The account to check
     * @return Whether the account has the role
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls role
     * @param role The role to check
     * @return The admin role
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants role to account
     * @param role The role to grant
     * @param account The account to grant the role to
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes role from account
     * @param role The role to revoke
     * @param account The account to revoke the role from
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes role from the calling account
     * @param role The role to renounce
     * @param account The account renouncing the role (must be msg.sender)
     */
    function renounceRole(bytes32 role, address account) external;
}
```

**FILES_TO_CREATE: `src/AccessControl.sol`**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./interfaces/IAccessControl.sol";

/**
 * @title AccessControl
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version based on OpenZeppelin's
 * AccessControl but optimized for Filecoin onramp use cases.
 * 
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests.
 * 
 * @notice This contract is designed to work seamlessly with Filecoin storage deals
 * and cross-chain bridge operations
 */
abstract contract AccessControl is IAccessControl {
    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    mapping(bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    // Filecoin onramp specific roles
    bytes32 public constant STORAGE_PROVIDER_ROLE = keccak256("STORAGE_PROVIDER_ROLE");
    bytes32 public constant DATA_CLIENT_ROLE = keccak256("DATA_CLIENT_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant BRIDGE_OPERATOR_ROLE = keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant DEAL_MAKER_ROLE = keccak256("DEAL_MAKER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with a standardized message including the required role.
     * @param role The role to check for
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /**
     * @dev See {IAccessControl-hasRole}.
     */
    function hasRole(bytes32 role, address account) public view virtual override returns (bool) {
        return _roles[role].members[account];
    }

    /**
     * @dev Revert with a standard message if `_msgSender()` is missing `role`.
     * Overriding this function changes the behavior of the {onlyRole} modifier.
     * @param role The role to check for
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Revert with a standard message if `account` is missing `role`.
     * @param role The role to check for
     * @param account The account to check
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert(
                string(
                    abi.encodePacked(
                        "AccessControl: account ",
                        _toHexString(uint160(account), 20),
                        " is missing role ",
                        _toHexString(uint256(role), 32)
                    )
                )
            );
        }
    }

    /**
     * @dev See {IAccessControl-getRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual override returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev See {IAccessControl-grantRole}.
     * 
     * Requirements:
     * - the caller must have ``role``'s admin role.
     * 
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev See {IAccessControl-revokeRole}.
     * 
     * Requirements:
     * - the caller must have ``role``'s admin role.
     * 
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev See {IAccessControl-renounceRole}.
     * 
     * Requirements:
     * - the caller must be `account`.
     * 
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address account) public virtual override {
        require(account == _msgSender(), "AccessControl: can only renounce roles for self");
        _revokeRole(role, account);
    }

    /**
     * @dev Grants `role` to `account`.
     * 
     * Internal function without access restriction.
     * 
     * May emit a {RoleGranted} event.
     * @param role The role to grant
     * @param account The account to grant the role to
     */
    function _grantRole(bytes32 role, address account) internal virtual {
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, _msgSender());
        }
    }

    /**
     * @dev Revokes `role` from `account`.
     * 
     * Internal function without access restriction.
     * 
     * May emit a {RoleRevoked} event.
     * @param role The role to revoke
     * @param account The account to revoke the role from
     */
    function _revokeRole(bytes32 role, address account) internal virtual {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, _msgSender());
        }
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     * 
     * Emits a {RoleAdminChanged} event.
     * @param role The role to set admin for
     * @param adminRole The admin role to set
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Returns the message sender for the current call
     * @return The address of the message sender
     */
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    /**
     * @dev Converts a uint256 to its ASCII string hexadecimal representation.
     * @param value The value to convert
     * @param length The expected length of the hex string
     * @return The hex string representation
     */
    function _toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";
}
```

**FILES_TO_CREATE: `test/AccessControl.t.sol`**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/AccessControl.sol";

contract AccessControlTestContract is AccessControl {
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function restrictedFunction() external onlyRole(DATA_CLIENT_ROLE) {
        // This function can only be called by accounts with DATA_CLIENT_ROLE
    }

    function adminFunction() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // This function can only be called by admins
    }
}

contract AccessControlTest is Test {
    AccessControlTestContract public accessControl;
    
    address public admin = address(0x1);
    address public dataClient = address(0x2);
    address public unauthorizedUser = address(0x3);

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant DATA_CLIENT_ROLE = keccak256("DATA_CLIENT_ROLE");
    bytes32 public constant STORAGE_PROVIDER_ROLE = keccak256("STORAGE_PROVIDER_ROLE");

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    function setUp() public {
        vm.prank(admin);
        accessControl = new AccessControlTestContract();
    }

    function testInitialAdminRole() public {
        assertTrue(accessControl.hasRole(DEFAULT_ADMIN_ROLE, admin));
        assertFalse(accessControl.hasRole(DEFAULT_ADMIN_ROLE, dataClient));
    }

    function testGrantRole() public {
        vm.prank(admin);
        
        vm.expectEmit(true, true, true, true);
        emit RoleGranted(DATA_CLIENT_ROLE, dataClient, admin);
        
        accessControl.grantRole(DATA_CLIENT_ROLE, dataClient);
        
        assertTrue(accessControl.hasRole(DATA_CLIENT_ROLE, dataClient));
    }

    function testRevokeRole() public {
        // First grant the role
        vm.prank(admin);
        accessControl.grantRole(DATA_CLIENT_ROLE, dataClient);
        
        // Then revoke it
        vm.prank(admin);
        
        vm.expectEmit(true, true, true, true);
        emit RoleRevoked(DATA_CLIENT_ROLE, dataClient, admin);
        
        accessControl.revokeRole(DATA_CLIENT_ROLE, dataClient);
        
        assertFalse(accessControl.hasRole(DATA_CLIENT_ROLE, dataClient));
    }

    function testRenounceRole() public {
        // Grant role first
        vm.prank(admin);
        accessControl.grantRole(DATA_CLIENT_ROLE, dataClient);
        
        // Renounce role
        vm.prank(dataClient);
        
        vm.expectEmit(true, true, true, true);
        emit RoleRevoked(DATA_CLIENT_ROLE, dataClient, dataClient);
        
        accessControl.renounceRole(DATA_CLIENT_ROLE, dataClient);
        
        assertFalse(accessControl.hasRole(DATA_CLIENT_ROLE, dataClient));
    }

    function testFailRenounceRoleForOthers() public {
        // Grant role first
        vm.prank(admin);
        accessControl.grantRole(DATA_CLIENT_ROLE, dataClient);
        
        // Try to renounce role for another account (should fail)
        vm.prank(unauthorizedUser);
        accessControl.renounceRole(DATA_CLIENT_ROLE, dataClient);
    }

    function testOnlyRoleModifier() public {
        // Grant role
        vm.prank(admin);
        accessControl.grantRole(DATA_CLIENT_ROLE, dataClient);
        
        // Should succeed
        vm.prank(dataClient);
        accessControl.restrictedFunction();
        
        // Should fail for unauthorized user
        vm.prank(unauthorizedUser);
        vm.expectRevert();
        accessControl.restrictedFunction();
    }

    function testFailGrantRoleUnauthorized() public {
        vm.prank(unauthorizedUser);
        accessControl.grantRole(DATA_CLIENT_ROLE, dataClient);
    }

    function testFailRevokeRoleUnauthorized() public {
        // Grant role first
        vm.prank(admin);
        accessControl.grantRole(DATA_CLIENT_ROLE, dataClient);
        
        // Try to revoke without permission
        vm.prank(unauthorizedUser);
        accessControl.revokeRole(DATA_CLIENT_ROLE, dataClient);
    }

    function testGetRoleAdmin() public {
        assertEq(accessControl.getRoleAdmin(DATA_CLIENT_ROLE), DEFAULT_ADMIN_ROLE);
    }

    function testFilecoinSpecificRoles() public {
        bytes32 storageProviderRole = keccak256("STORAGE_PROVIDER_ROLE");
        bytes32 oracleRole = keccak256("ORACLE_ROLE");
        bytes32 bridgeOperatorRole = keccak256("BRIDGE_OPERATOR_ROLE");
        
        // Test that roles are properly defined
        assertEq(accessControl.STORAGE_PROVIDER_ROLE(), storageProviderRole);
        assertEq(accessControl.ORACLE_ROLE(), oracleRole);
        assertEq(accessControl.BRIDGE_OPERATOR_ROLE(), bridgeOperatorRole);
    }
}
```

**FILES_TO_CREATE: `test/OnRampAccessControl.t.sol`**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/OnRamp.sol";
import "../src/Token.sol";

contract OnRampAccessControlTest is Test {
    OnRamp public onRamp;
    Nickle public token;
    
    address public admin = address(0x1);
    address public dataClient = address(0x2);
    address public verifier = address(0x3);
    address public unauthorized = address(0x4);
    
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant DATA_CLIENT_ROLE = keccak256("DATA_CLIENT_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    function setUp() public {
        vm.prank(admin);
        onRamp = new OnRamp();
        
        // Deploy token and mint some to accounts
        token = new Nickle();
        token.transfer(dataClient, 1000e18);
        
        // Grant roles
        vm.startPrank(admin);
        onRamp.grantRole(DATA_CLIENT_ROLE, dataClient);
        onRamp.grantRole(VERIFIER_ROLE, verifier);
        vm.stopPrank();
    }

    function testSubmitDataWithRole() public {
        bytes memory data = "test data";
        bytes32 commitment = keccak256(data);
        
        vm.prank(dataClient);
        token.approve(address(onRamp), 100e18);
        
        vm.prank(dataClient);
        // This should succeed with proper role
        onRamp.submitData(data, commitment, address(token), 100e18);
    }

    function testFailSubmitDataWithoutRole() public {
        bytes memory data = "test data";
        bytes32 commitment = keccak256(data);
        
        vm.prank(unauthorized);
        token.approve(address(onRamp), 100e18);
        
        vm.prank(unauthorized);
        // This should fail without proper role
        onRamp.submitData(data, commitment, address(token), 100e18);
    }

    function testVerifyWithRole() public {
        // Setup some data first
        bytes memory data = "test data";
        bytes32 commitment = keccak256(data);
        
        vm.prank(dataClient);
        token.approve(address(onRamp), 100e18);
        
        vm.prank(dataClient);
        onRamp.submitData(data, commitment, address(token), 100e18);
        
        // Mock proof data
        PODSIVerifier.ProofData memory proof = PODSIVerifier.ProofData({
            index: 0,
            path: new bytes32[](0)
        });
        
        vm.prank(verifier);
        // This should succeed with proper role
        onRamp.verifyInclusion(commitment, commitment, proof);
    }

    function testFailVerifyWithoutRole() public {
        // Setup some data first
        bytes memory data = "test data";
        bytes32 commitment = keccak256(data);
        
        vm.prank(dataClient);
        token.approve(address(onRamp), 100e18);
        
        vm.prank(dataClient);
        onRamp.submitData(data, commitment, address(token), 100e18);
        
        // Mock proof data
        PODSIVerifier.ProofData memory proof = PODSIVerifier.ProofData({
            index: 0,
            path: new bytes32[](0)
        });
        
        vm.prank(unauthorized);
        // This should fail without proper role
        onRamp.verifyInclusion(commitment, commitment, proof);
    }

    function testRoleAdminCanManageRoles() public {
        address newDataClient = address(0x5);
        
        vm.prank(admin);
        onRamp.grantRole(DATA_CLIENT_ROLE, newDataClient);
        
        assertTrue(onRamp.hasRole(DATA_CLIENT_ROLE, newDataClient));
        
        vm.prank(admin);
        onRamp.revokeRole(DATA_CLIENT_ROLE, newDataClient);
        
        assertFalse(onRamp.hasRole(DATA_CLIENT_ROLE, newDataClient));
    }
}
```

### MODIFIED FILES

**FILES_TO_MODIFY: `src/OnRamp.sol`**

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {IERC20} from "../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Cid} from "./Cid.sol";
import {TRUNCATOR} from "./Const.sol";
import {DataAttestation} from "./Oracles.sol";
import {AccessControl} from "./AccessControl.sol";

// Adapted from https://github.com/lighthouse-web3/raas-starter-kit/blob/main/contracts/data-segment/Proof.sol
// adapted rather than imported to
//  1) avoid build issues
//  2) avoid npm deps
//3)  avoid use of deprecated @zondax/filecoin-solidity
contract PODSIVerifier {
    // ProofData is a Merkle proof
    struct ProofData {
        uint64 index;
        bytes32[] path;
    }

    // verify verifies that the given leaf is present in the merkle tree with the given root.
    function verify(
        ProofData memory proof,
        bytes32 root,
        bytes32 leaf
    ) public pure returns (bool) {
        return computeRoot(proof, leaf) == root;
    }

    // computeRoot computes the root of a Merkle tree given a leaf and a Merkle proof.
    function computeRoot(
        ProofData memory d,
        bytes32 subtree
    ) internal pure returns (bytes32) {
        require(
            d.path.length < 64,
            "merkleproofs with depths greater than 63 are not supported"
        );
        require(
            d.index >> d.path.length == 0,
            "index greater than width of the tree"
        );

        bytes32 carry = subtree;
        uint64 index = d.index;
        uint64 right = 0;

        for (uint64 i = 0; i < d.path.length; i++) {
            (right, index) = (index & 1, index >> 1);
            if (right == 1) {
                carry = sha256(abi.encodePacked(d.path[i], carry));
            } else {
                carry = sha256(abi.encodePacked(carry, d.path[i]));
            }
        }
        return carry;
    }
}

/**
 * @title OnRamp
 * @dev Main contract for submitting data to Filecoin network with RBAC
 * @notice This contract allows users to submit data for storage on Filecoin
 * and verify storage proofs with proper access control
 */
contract OnRamp is PODSIVerifier, AccessControl {
    struct Submission {
        bytes32 dataCommitment;
        address submitter;
        address paymentToken;
        uint256 paymentAmount;
        uint256 timestamp;
        bool verified;
    }

    mapping(bytes32 => Submission) public submissions;
    mapping(bytes32 => bytes32) public dataCommitmentToRoot; // Maps data commitment to merkle root

    /// @notice Emitted when data is submitted for storage
    event DataSubmitted(
        bytes32 indexed dataCommitment,
        address indexed submitter,
        address paymentToken,
        uint256 paymentAmount
    );

    /// @notice Emitted when storage is verified
    event StorageVerified(
        bytes32 indexed dataCommitment,
        bytes32 indexed merkleRoot,
        address indexed verifier
    );

    /// @notice Emitted when storage proof attestation is received
    event StorageAttestationReceived(
        bytes32 indexed dataCommitment,
        uint64 indexed dealId,
        address indexed submitter
    );

    /**
     * @dev Constructor sets up access control with deployer as admin
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        // Set up role hierarchy - admins can manage all roles
        _setRoleAdmin(DATA_CLIENT_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(VERIFIER_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(STORAGE_PROVIDER_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(ORACLE_ROLE, DEFAULT_ADMIN_ROLE);
    }

    /**
     * @notice Submit data for storage on Filecoin
     * @dev Only accounts with DATA_CLIENT_ROLE can submit data
     * @param data The data to store
     * @param dataCommitment Commitment hash of the data
     * @param paymentToken Token to use for payment
     * @param paymentAmount Amount to pay for storage
     */
    function submitData(
        bytes calldata data,
        bytes32 dataCommitment,
        address paymentToken,
        uint256 paymentAmount
    ) external onlyRole(DATA_CLIENT_ROLE) {
        require(data.length > 0, "OnRamp: empty data");
        require(dataCommitment != bytes32(0), "OnRamp: invalid commitment");
        require(paymentToken != address(0), "OnRamp: invalid payment token");
        require(paymentAmount > 0, "OnRamp: invalid payment amount");
        require(submissions[dataCommitment].submitter == address(0), "OnRamp: data already submitted");

        // Verify commitment matches data
        require(keccak256(data) == dataCommitment, "OnRamp: commitment mismatch");

        // Transfer payment
        IERC20(paymentToken).transferFrom(msg.sender, address(this), paymentAmount);

        // Store submission
        submissions[dataCommitment] = Submission({
            dataCommitment: dataCommitment,
            submitter: msg.sender,
            paymentToken: paymentToken,
            paymentAmount: paymentAmount,
            timestamp: block.timestamp,
            verified: false
        });

        emit DataSubmitted(dataCommitment, msg.sender, paymentToken, paymentAmount);
    }

    /**
     * @notice Verify that data is included in a Filecoin sector
     * @dev Only accounts with VERIFIER_ROLE can verify inclusion
     * @param dataCommitment The commitment of the stored data
     * @param merkleRoot The merkle root of the sector
     * @param proof Merkle proof showing inclusion
     */
    function verifyInclusion(
        bytes32 dataCommitment,
        bytes32 merkleRoot,
        ProofData calldata proof
    ) external onlyRole(VERIFIER_ROLE) {
        require(submissions[dataCommitment].submitter != address(0), "OnRamp: data not found");
        require(!submissions[dataCommitment].verified, "OnRamp: already verified");

        // Verify merkle proof
        require(verify(proof, merkleRoot, dataCommitment), "OnRamp: invalid proof");

        // Mark as verified
        submissions[dataCommitment].verified = true;
        dataCommitmentToRoot[dataCommitment] = merkleRoot;

        emit StorageVerified(dataCommitment, merkleRoot, msg.sender);
    }

    /**
     * @notice Handle storage attestation from oracle
     * @dev Only accounts with ORACLE_ROLE can submit attestations
     * @param attestation The storage attestation data
     */
    function proveDataStored(DataAttestation calldata attestation) 
        external 
        onlyRole(ORACLE_ROLE) 
    {
        bytes32 dataCommitment = Cid.cidToPieceCommitment(attestation.commP);
        require(submissions[dataCommitment].submitter != address(0), "OnRamp: data not found");

        // Additional verification logic based on attestation
        require(attestation.status == 1, "OnRamp: deal not active"); // Assuming 1 = active
        require(attestation.duration > 0, "OnRamp: invalid duration");

        emit StorageAttestationReceived(
            dataCommitment,
            attestation.FILID,
            submissions[dataCommitment].submitter
        );
    }

    /**
     * @notice Get submission details
     * @param dataCommitment The data commitment to query
     * @return The submission details
     */
    function getSubmission(bytes32 dataCommitment) 
        external 
        view 
        returns (Submission memory) 
    {
        return submissions[dataCommitment];
    }

    /**
     * @notice Check if data has been verified
     * @param dataCommitment The data commitment to check
     * @return Whether the data has been verified
     */
    function isVerified(bytes32 dataCommitment) external view returns (bool) {
        return submissions[dataCommitment].verified;
    }

    /**
     * @notice Emergency withdrawal function for admins
     * @dev Only DEFAULT_ADMIN_ROLE can withdraw funds
     * @param token The token to withdraw
     * @param to The address to send tokens to
     * @param amount The amount to withdraw
     */
    function emergencyWithdraw(
        address token,
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(to != address(0), "OnRamp: invalid recipient");
        IERC20(token).transfer(to, amount);
    }

    /**
     * @notice Batch grant roles to multiple accounts
     * @dev Only admin can batch grant roles
     * @param role The role to grant
     * @param accounts The accounts to grant the role to
     */
    function batchGrantRole(bytes32 role, address[] calldata accounts) 
        external 
        onlyRole(getRoleAdmin(role)) 
    {
        for (uint256 i = 0; i < accounts.length; i++) {
            _grantRole(role, accounts[i]);
        }
    }

    /**
     * @notice Batch revoke roles from multiple accounts
     * @dev Only admin can batch revoke roles
     * @param role The role to revoke
     
```
