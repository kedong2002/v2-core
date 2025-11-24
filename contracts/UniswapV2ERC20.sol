// SPDX-License-Identifier: MIT

// Upgraded to a modern, secure Solidity version (built-in overflow checks).
pragma solidity ^0.8.20;

import './interfaces/IUniswapV2ERC20.sol';
// SafeMath is no longer needed since Solidity 0.8.0+ handles overflow/underflow checks natively.

/**
 * @title UniswapV2ERC20
 * @notice The liquidity provider token used by the Uniswap V2 protocol.
 * Includes EIP-2612 (Permit) functionality.
 */
contract UniswapV2ERC20 is IUniswapV2ERC20 {

    // --- ERC-20 Standard Metadata ---
    string public constant name = 'Uniswap V2';
    string public constant symbol = 'UNI-V2';
    uint8 public constant decimals = 18;
    
    // --- ERC-20 State ---
    uint public totalSupply;
    mapping(address => uint) public balanceOf;
    mapping(address => mapping(address => uint)) public allowance;

    // --- EIP-2612 Permit State ---
    bytes32 public immutable DOMAIN_SEPARATOR; // Immutable for security and gas efficiency
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    mapping(address => uint) public nonces;

    // --- Events ---
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    constructor() {
        // Calculate DOMAIN_SEPARATOR using EIP-712 standard components.
        // In 0.8.x, block.chainid is used directly instead of assembly.
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
                keccak256(bytes(name)),
                keccak256(bytes('1')), // Note: version is '1' for Uniswap V2
                block.chainid,
                address(this)
            )
        );
    }

    // --- Internal/Private Logic (0.8.x math safety used implicitly) ---

    function _mint(address to, uint value) internal {
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    function _burn(address from, uint value) internal {
        balanceOf[from] -= value;
        totalSupply -= value;
        emit Transfer(from, address(0), value);
    }

    function _approve(address owner, address spender, uint value) private {
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function _transfer(address from, address to, uint value) private {
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    // --- External ERC-20 Functions ---

    function approve(address spender, uint value) external returns (bool) {
        _approve(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint value) external returns (bool) {
        // Check for infinite allowance. If allowance is MAX_UINT, skip deduction.
        if (allowance[from][msg.sender] != type(uint).max) { 
            // Deduct allowance. This subtraction is safe in 0.8.x.
            allowance[from][msg.sender] -= value; 
        }
        _transfer(from, to, value);
        return true;
    }

    // --- EIP-2612 Permit Function ---
    
    /**
     * @notice Allows an owner to pre-sign a transaction authorizing a spender to spend tokens.
     * @dev Uses EIP-712 signed messages to approve spending without sending a transaction.
     */
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
        // 1. Check if the signature has expired.
        require(deadline >= block.timestamp, 'UniswapV2: PERMIT_EXPIRED');
        
        // 2. Hash the EIP-712 payload.
        bytes32 digest = keccak256(
            abi.encodePacked(
                '\x19\x01', // EIP-712 prefix
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        PERMIT_TYPEHASH,
                        owner,
                        spender,
                        value,
                        // Increment nonce after use (safe in 0.8.x)
                        nonces[owner]++, 
                        deadline
                    )
                )
            )
        );
        
        // 3. Recover the signing address and verify it matches the owner.
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress != address(0) && recoveredAddress == owner, 'UniswapV2: INVALID_SIGNATURE_OR_OWNER');
        
        // 4. Set the allowance (equivalent to calling approve).
        _approve(owner, spender, value);
    }
}
