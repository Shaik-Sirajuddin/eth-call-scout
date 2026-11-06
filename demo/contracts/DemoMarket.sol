// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract DemoToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory tokenName, string memory tokenSymbol) {
        name = tokenName;
        symbol = tokenSymbol;
    }

    function mint(address recipient, uint256 amount) external {
        totalSupply += amount;
        balanceOf[recipient] += amount;
        emit Transfer(address(0), recipient, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function transferFrom(address owner, address recipient, uint256 amount) external returns (bool) {
        uint256 approved = allowance[owner][msg.sender];
        require(approved >= amount, "allowance");
        if (approved != type(uint256).max) {
            allowance[owner][msg.sender] = approved - amount;
        }
        _transfer(owner, recipient, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
contract UnsafeTarget {
    event UnexpectedCall(address indexed wallet, uint256 marker);

    function touch(address wallet) external {
        emit UnexpectedCall(wallet, 0xBAD);
    }
}

contract DemoRouter {
    DemoToken public immutable tokenIn;
    DemoToken public immutable tokenOut;
    address public immutable unsafeTarget;
    address public immutable operator;
    bool public unsafeMode;
    bool public paused;

    event SwapExecuted(
        address indexed wallet,
        address indexed recipient,
        uint256 amountIn,
        uint256 amountOut
    );

    constructor(address inputToken, address outputToken, address unsafeContract) {
        tokenIn = DemoToken(inputToken);
        tokenOut = DemoToken(outputToken);
        unsafeTarget = unsafeContract;
        operator = msg.sender;
    }

    function setUnsafeMode(bool enabled) external {
        require(msg.sender == operator, "operator");
        unsafeMode = enabled;
    }

    function setPaused(bool enabled) external {
        require(msg.sender == operator, "operator");
        paused = enabled;
    }

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 minimumOut,
        address recipient
    ) external returns (uint256 amountOut) {
        require(!paused, "paused");
        require(recipient != address(0), "recipient");
        amountOut = amountIn * 2;
        require(amountOut >= minimumOut, "slippage");
        require(tokenIn.transferFrom(msg.sender, address(this), amountIn), "input");
        require(tokenOut.transfer(recipient, amountOut), "output");
        if (unsafeMode) UnsafeTarget(unsafeTarget).touch(msg.sender);
        emit SwapExecuted(msg.sender, recipient, amountIn, amountOut);
    }
}

