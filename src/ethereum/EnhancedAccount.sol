// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Import required libraries and interfaces
import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title EnhancedAccount
 * @notice Extends ERC-4337's account functionality with additional features:
 * - EIP-7702 support (batch operations and tokenized permissioning)
 * - Multi-Factor Authentication (MFA)
 * - Spending limits
 * - Social recovery
 * 
 * This version utilizes EIP-1153 transient storage (TSTORE, TLOAD) for optimized storage operations.
 */
contract EnhancedAccount is IAccount, Ownable {
    // Immutable EntryPoint address for ERC-4337 transactions
    IEntryPoint private immutable i_entryPoint;

    // Mutable state variables for spending limits and guardians.
    address public secondaryKey; // Secondary key for MFA
    mapping(bytes32 => bool) public usedOtps; // Tracks used OTPs

    uint256 public dailyLimit; // Max ETH allowed per day
    uint256 public dailySpent; // Total ETH spent today
    uint256 public lastSpendReset; // Timestamp of last daily reset
    mapping(address => bool) public whitelist; // Addresses allowed to bypass limit
    mapping(address => bool) public blacklist; // Addresses blocked from spending

    address[] public guardians; // List of guardians for social recovery
    uint256 public recoveryThreshold; // Number of approvals required for recovery
    mapping(address => bool) public isGuardian; // Guardian status

    event BatchApproved(address indexed operator, bytes data);
    event BatchOperationResult(uint256 index, address dest, bool success);
    event SecondaryKeySet(address indexed newKey);
    event OTPUsed(bytes32 indexed otp);
    event DailyLimitSet(uint256 newLimit);
    event TransactionExecuted(address indexed dest, uint256 value, bool success);
    event AddressWhitelisted(address indexed addr);
    event AddressBlacklisted(address indexed addr);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event RecoveryTriggered(address indexed newOwner);

    // Constructor to initialize the contract with an initial owner and entry point
    constructor(address initialOwner, IEntryPoint entryPoint) Ownable(initialOwner) {
        require(initialOwner != address(0), "EnhancedAccount: Invalid owner address");
        i_entryPoint = entryPoint;
    }

    // ERC-7715: Permission types

    // Add a new struct to store permission with expiration time
    struct Permission {
        bool granted;
        uint256 expiresAt; // Timestamp when permission expires
    }

    enum PermissionType { SEND_FUNDS, SIGN_MESSAGE, EXECUTE_CALL }
    mapping(address => mapping(PermissionType => Permission)) public permissions;

    event PermissionGranted(address indexed account, PermissionType permission, uint256 expiresAt);
    event PermissionRevoked(address indexed account, PermissionType permission);


    // --- ERC-7715 Tokenized Permissioning ---
    // Modifier update to check expiration before allowing actions
    modifier onlyWithPermission(PermissionType permission) {
        require(
            permissions[msg.sender][permission].granted &&
            permissions[msg.sender][permission].expiresAt > block.timestamp,
            "No valid permission"
        );
        _;
    }
    // Updated function to grant permission with an optional expiration time
    function grantPermission(address account, PermissionType permission, uint256 duration) external onlyOwner {
        uint256 expiryTime = duration > 0 ? block.timestamp + duration : type(uint256).max;
        permissions[account][permission] = Permission(true, expiryTime);
        emit PermissionGranted(account, permission, expiryTime);
    }
    // Updated function to revoke permission
    function revokePermission(address account, PermissionType permission) external onlyOwner {
        delete permissions[account][permission];
        emit PermissionRevoked(account, permission);
    }

    function executeWithPermission(
        address dest,
        uint256 value,
        bytes calldata data
    ) external onlyWithPermission(PermissionType.EXECUTE_CALL) {
        (bool success, ) = dest.call{value: value}(data);
        require(success, "Execution failed");
    }

    function sendFundsWithPermission(address payable to, uint256 amount)
        external onlyWithPermission(PermissionType.SEND_FUNDS)
    {
        require(address(this).balance >= amount, "Insufficient balance");
        to.transfer(amount);
    }

    function signMessageWithPermission(bytes32 hash, bytes memory signature)
        external view onlyWithPermission(PermissionType.SIGN_MESSAGE)
        returns (bool)
    {
        return ECDSA.recover(hash, signature) == owner();
    }

    // --- EIP-7702: Batch Processing and Approvals ---
    /**
     * @notice Executes multiple operations in a single transaction using EIP-1153 transient storage.
     * @param dests List of destination addresses.
     * @param values List of ETH amounts to send.
     * @param data List of calldata for each destination.
     */
    function executeBatchWithTransient(
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata data
    ) external onlyOwner {
        require(
            dests.length == values.length && dests.length == data.length,
            "EnhancedAccount: Length mismatch"
        );

        // Calculate total value to send
        uint256 totalValue = 0; 
        for (uint256 i = 0; i < values.length; i++) {
            totalValue += values[i];
        }
        
        // Store totalValue in transient storage using TSTORE (EIP-1153 opcode)
        assembly {
            tstore(0, totalValue) // Store total value in transient storage
        }

        // Retrieve totalValue from transient storage using TLOAD (EIP-1153 opcode)
        uint256 storedTotalValue;
        assembly {
            storedTotalValue := tload(0) // Retrieve total value from transient storage
        }

        require(address(this).balance >= storedTotalValue, "EnhancedAccount: Insufficient balance");

        for (uint256 i = 0; i < dests.length; i++) {
            (bool success, ) = dests[i].call{value: values[i]}(data[i]);
            emit BatchOperationResult(i, dests[i], success);
            require(success, "EnhancedAccount: Batch operation failed");
        }

        emit BatchApproved(msg.sender, abi.encode(dests, values, data));
    }

    // Original batch function for comparison (currently unchanged)
    function executeBatch(
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata data
    ) external onlyOwner {
        // Identical to `executeBatchWithTransient`
        // Keeping this for performance comparison
    }
    
    /**
     * @notice Allows the account owner to approve ERC-20 tokens for gasless transactions.
     * @param token The ERC-20 token contract.
     * @param spender The spender address.
     * @param amount The amount of tokens to approve.
     */
    function approveERC20(address token, address spender, uint256 amount) external onlyOwner {
        IERC20(token).approve(spender, amount);
    }

    // --- Multi-Factor Authentication (MFA) ---
    /**
     * @notice Sets a secondary key for MFA.
     * @param newKey The new secondary key.
     */
    function setSecondaryKey(address newKey) external onlyOwner {
        secondaryKey = newKey;
        emit SecondaryKeySet(newKey);
    }

    /**
     * @notice Executes a transaction with MFA.
     * @param dest The destination address.
     * @param value The ETH amount to send.
     * @param data The calldata for the transaction.
     * @param otp A one-time password for additional security.
     * @param secondarySignature Signature from the secondary key for the OTP.
     */
    function executeWithMFA(
        address dest,
        uint256 value,
        bytes calldata data,
        bytes32 otp,
        bytes memory secondarySignature
    ) external onlyOwner {
        // Prevent OTP reuse
        require(!usedOtps[otp], "EnhancedAccount: OTP already used");
        usedOtps[otp] = true;

        // Verify the OTP with the secondary key's signature
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(abi.encodePacked(otp));
        address recoveredKey = ECDSA.recover(ethSignedMessageHash, secondarySignature);

        require(recoveredKey == secondaryKey, "EnhancedAccount: Invalid secondary signature");

        // Execute the transaction
        (bool success, ) = dest.call{value: value}(data);
        require(success, "EnhancedAccount: MFA transaction failed");

        emit OTPUsed(otp);
    }

    // --- Spending Limits ---
    /**
     * @notice Sets a daily spending limit.
     * @param limit The new daily limit in wei.
     */
    function setDailyLimit(uint256 limit) external onlyOwner {
        dailyLimit = limit;
        emit DailyLimitSet(limit);
    }

    /**
     * @notice Adds an address to the whitelist.
     * @param addr The address to whitelist.
     */
    function addToWhitelist(address addr) external onlyOwner {
        whitelist[addr] = true;
        emit AddressWhitelisted(addr);
    }

    /**
     * @notice Adds an address to the blacklist.
     * @param addr The address to blacklist.
     */
    function addToBlacklist(address addr) external onlyOwner {
        blacklist[addr] = true;
        emit AddressBlacklisted(addr);
    }

    /**
     * @notice Executes a transaction with spending limits enforced using EIP-1153 transient storage.
     * @param dest The destination address.
     * @param value The ETH amount to send.
     * @param data The calldata for the transaction.
     */
    function executeWithLimitTransient(address dest, uint256 value, bytes calldata data) external onlyOwner {
        // Load daily spent and last spend reset timestamps from transient storage
        uint256 tempDailySpent;
        uint256 tempLastSpendReset;

        assembly {
            tempDailySpent := tload(1) // Load transient value for daily spent
            tempLastSpendReset := tload(2) // Load transient value for last spend reset
        }

        // Reset daily spending if it's a new day
        if (block.timestamp > tempLastSpendReset + 1 days) {
            tempDailySpent = 0;
            tempLastSpendReset = block.timestamp ;
        }

        require(!blacklist[dest], "EnhancedAccount: Address is blacklisted");
        if (!whitelist[dest]) {
            require(tempDailySpent + value <= dailyLimit, "EnhancedAccount: Exceeds daily limit");
        }

        // Update the transient daily spent value
        tempDailySpent += value;

        // Execute the transaction
        (bool success, ) = dest.call{value: value}(data);
        emit TransactionExecuted(dest, value, success);
        require(success, "EnhancedAccount: Spending limit transaction failed");

        // Save updated values back to transient storage
        assembly {
            tstore(1, tempDailySpent) // Store updated daily spent
            tstore(2, tempLastSpendReset) // Update last spend reset timestamp
        }

        // Finally, update persistent storage
        dailySpent = tempDailySpent;
        lastSpendReset = tempLastSpendReset;
    }

    // --- Social Recovery ---
    /**
     * @notice Adds a guardian for social recovery.
     * @param guardian The guardian's address.
     */
    function addGuardian(address guardian) external onlyOwner {
        require(!isGuardian[guardian], "EnhancedAccount: Already a guardian");
        isGuardian[guardian] = true;
        guardians.push(guardian);
        emit GuardianAdded(guardian);
    }

    /**
     * @notice Removes a guardian.
     * @param guardian The guardian's address.
     */
    function removeGuardian(address guardian) external onlyOwner {
        require(isGuardian[guardian], "EnhancedAccount: Not a guardian");
        isGuardian[guardian] = false;

        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == guardian) {
                guardians[i] = guardians[guardians.length - 1];
                guardians.pop();
                break;
            }
        }

        emit GuardianRemoved(guardian);
    }

    /**
     * @notice Triggers account recovery.
     * @param newOwner The address to transfer ownership to.
     * @param guardianSignatures The signatures of the guardians approving the recovery.
     */
    function triggerRecovery(
        address newOwner,
        bytes[] calldata guardianSignatures
    ) external {
        require(
            guardianSignatures.length >= recoveryThreshold,
            "EnhancedAccount: Not enough approvals"
        );

        bytes32 messageHash = keccak256(abi.encodePacked(newOwner, address(this)));
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);

        uint256 validApprovals = 0;
        for (uint256 i = 0; i < guardianSignatures.length; i++) {
            address recoveredGuardian = ECDSA.recover(ethSignedMessageHash, guardianSignatures[i]);
            if (isGuardian[recoveredGuardian]) validApprovals++;
        }

        require(validApprovals >= recoveryThreshold, "EnhancedAccount: Invalid approvals");

        _transferOwnership(newOwner);
        emit RecoveryTriggered(newOwner);
    }

    // Internal function for ownership transfer with override
    function _transferOwnership(address newOwner) internal override {
        Ownable._transferOwnership(newOwner); // Use OpenZeppelin's implementation
    }

    // --- ERC-4337 Functions ---
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        if (ECDSA.recover(userOpHash, userOp.signature) != owner()) {
            return 1; // Invalid signature
        }
        _payPrefund(missingAccountFunds);
        return 0;
    }

    function _payPrefund(uint256 amount) internal {
        if (amount > 0) {
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "EnhancedAccount: Prefund failed");
        }
    }

    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }

    // Fallback function to receive ETH
    receive() external payable {}

    // --- Combined Batch MFA with Transient Storage ---
    /**
     * @notice Executes multiple operations in a single transaction with MFA and transient storage.
     * @param dests List of destination addresses.
     * @param values List of ETH amounts to send.
     * @param data List of calldata for each destination.
     * @param otp A one-time password for additional security.
     * @param secondarySignature Signature from the secondary key for the OTP.
     */
    function executeBatchWithMFAAndTransient(
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata data,
        bytes32 otp,
        bytes memory secondarySignature
    ) external onlyOwner {
        // Prevent OTP reuse
        require(!usedOtps[otp], "EnhancedAccount: OTP already used");
        usedOtps[otp] = true;

        // Verify the OTP with the secondary key's signature
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(abi.encodePacked(otp));
        address recoveredKey = ECDSA.recover(ethSignedMessageHash, secondarySignature);
        require(recoveredKey == secondaryKey, "EnhancedAccount: Invalid secondary signature");

        require(
            dests.length == values.length && dests.length == data.length,
            "EnhancedAccount: Length mismatch"
        );

        // Calculate total value to send and store in transient storage
        uint256 totalValue = 0;
        for (uint256 i = 0; i < values.length; i++) {
            totalValue += values[i];
        }
        
        // Store totalValue in transient storage using TSTORE (EIP-1153 opcode)
        assembly {
            tstore(0, totalValue) // Store total value in transient storage
        }

        // Retrieve totalValue from transient storage using TLOAD (EIP-1153 opcode)
        uint256 storedTotalValue;
        assembly {
            storedTotalValue := tload(0) // Retrieve total value from transient storage
        }

        require(address(this).balance >= storedTotalValue, "EnhancedAccount: Insufficient balance");

        // Execute batch operations
        for (uint256 i = 0; i < dests.length; i++) {
            (bool success, ) = dests[i].call{value: values[i]}(data[i]);
            emit BatchOperationResult(i, dests[i], success);
            require(success, "EnhancedAccount: Batch operation failed");
        }

        emit BatchApproved(msg.sender, abi.encode(dests, values, data));
        emit OTPUsed(otp);
    }
}