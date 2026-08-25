// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Reference source for the creation bytecode checked into `MockERC20.bin`, which
// `src/erc20.rs` embeds via `include_str!`. Cargo does not invoke solc — only `anvil` needs to be
// on PATH to run these tests, so the bytecode is precompiled rather than compiled at test time.
//
// To regenerate after editing this file:
//   forge init --no-git --no-commit /tmp/mockerc20-build
//   cp MockERC20.sol /tmp/mockerc20-build/src/
//   cd /tmp/mockerc20-build && forge build --optimize --optimizer-runs 200 --use 0.8.24
//   jq -r '.bytecode.object' out/MockERC20.sol/MockERC20.json > MockERC20.bin
// (no trailing newline needed; `include_str!` + `.trim()` tolerates one either way)
// Compiled with: solc 0.8.24, optimizer on (200 runs), bytecode_hash = none, cbor_metadata = false.

/// Minimal ERC-20 with a constructor-configurable `decimals`, used only by the Octo Anvil test
/// harness to exercise decimal handling (6 / 18 / 0) against a real deployed contract. Not for
/// production use — no access control beyond `mint` being owner-only.
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory name_, string memory symbol_, uint8 decimals_, uint256 initialSupply) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        owner = msg.sender;
        if (initialSupply > 0) {
            _mint(msg.sender, initialSupply);
        }
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "MockERC20: not owner");
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "MockERC20: insufficient allowance");
        allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "MockERC20: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
