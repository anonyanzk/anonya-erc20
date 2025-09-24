// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Time as T }      from "@openzeppelin/contracts/utils/types/Time.sol";
import { Math as M }      from "@openzeppelin/contracts/utils/math/Math.sol";
import { ECDSA }          from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 }         from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { Nonces }         from "@openzeppelin/contracts/utils/Nonces.sol";
import { Address }        from "@openzeppelin/contracts/utils/Address.sol";
import { Context }        from "@openzeppelin/contracts/utils/Context.sol";
import { Strings }        from "@openzeppelin/contracts/utils/Strings.sol";
import { ShortString, 
         ShortStrings }   from "@openzeppelin/contracts/utils/ShortStrings.sol";
import { TransientSlot }  from "@openzeppelin/contracts/utils/TransientSlot.sol";
import { SlotDerivation } from "@openzeppelin/contracts/utils/SlotDerivation.sol";

import { IERC20 }                from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Permit }          from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import { IERC20Errors  }         from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { IERC20Metadata }        from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { IERC7674 }              from "@openzeppelin/contracts/interfaces/draft-IERC7674.sol";
import { IERC3156FlashBorrower } from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import { IERC3156FlashLender }   from "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";

/**
 * @title  ERC-20 token with extensions (EIP-2612, ERC-3156, ERC-7674).
 * @notice Extended ERC-20 implementation supporting flash loans, transient approvals, and off-chain signatures.
 * @author @anonyanzk
 * @custom:social X(Twitter) https://x.com/anonyanzk
 * @custom:social Telegram   https://t.me/anonyantg
 * @custom:source https://github.com/anonyanzk/anonya-erc20
 * @dev Decentralized token with capped total supply and burn mechanisms.
 */
contract AnonyaERC20 is 
    IERC20, 
    IERC20Metadata, 
    IERC20Errors, 
    IERC7674, 
    IERC20Permit, 
    IERC3156FlashLender,
    EIP712,
    Nonces,
    Context
{
    using ShortStrings    for *;
    using SlotDerivation  for bytes32;
    using TransientSlot   for bytes32;
    using TransientSlot   for TransientSlot.Uint256Slot;
    
    /* ───────────────────────────── Errors ──────────────────────────────── */
    /**
     * @dev Reverts when minting would push the total supply above the cap.
     * @param newSupply The total supply that would result after minting.
     * @param cap       The maximum allowed supply.
     */
    error ERC20MintCapExceeded(uint256 newSupply, uint256 cap);

    /**
     * @dev Reverts when the recovered signer does not match the expected owner.
     * @param signer The recovered address from the signature.
     * @param owner  The expected token owner.
     */
    error ERC2612InvalidSigner(address signer, address owner);

    /**
     * @dev Reverts when the permit signature has expired.
     * @param deadline The timestamp after which the signature is invalid.
     */
    error ERC2612ExpiredSignature(uint256 deadline);

    /**
     * @dev Reverts when the loan amount is zero.
     * @param amount The invalid loan amount.
     */
    error ERC3156ZeroAmount(uint256 amount);

    /**
     * @dev Reverts when the loan amount exceeds the maximum loanable amount.
     * @param maxLoan The maximum loanable amount.
     */
    error ERC3156ExceededMaxLoan(uint256 maxLoan);

    /**
     * @dev Reverts when the given token is not supported for flash loans.
     * @param token The unsupported token address.
     */
    error ERC3156UnsupportedToken(address token);

    /**
     * @dev Reverts when the flash loan receiver callback returns an unexpected value.
     * @param receiver The receiver contract address.
     */
    error ERC3156InvalidReceiver(address receiver);

    /**
     * @dev Reverts when the token name constructor parameter is empty.
     */
    error EmptyInitialName();

    /**
     * @dev Reverts when the token symbol constructor parameter is empty.
     */
    error EmptyInitialSymbol();

    /**
     * @dev Reverts when the initial supply constructor parameter is zero.
     */
    error ZeroInitialSupply();

    /**
     * @dev Reverts when the fee receiver constructor parameter is the zero address.
     */
    error InvalidFeeReceiver();

    /**
     * @dev Reverts when the provided cap is not greater than the initial supply,
     *      preventing flash-minting.
     * @param initialSupply The initial minted amount.
     * @param cap           The provided cap value.
     */
    error InvalidInitialCap(uint256 initialSupply, uint256 cap);

    /**
     * @dev Reverts on reentrant call.
     */
    error ReentrantCall();

    /**
     * @dev Reverts when receiving ETH via receive.
     * @param sender The caller that sent ETH.
     * @param value  The amount of ETH sent.
     */
    error ReceiveDisable(address sender, uint256 value);

    /**
     * @dev Reverts when invoked via fallback.
     * @param sender The caller that triggered the fallback.
     * @param value  The amount of ETH sent with the call.
     * @param data   The calldata passed to the fallback.
     */
    error FallbackDisable(address sender, uint256 value, bytes data);

    // ───────────────────────────── Events ────────────────────────────────
    /**
     * @dev Emitted when temporaryApproveAndCall is executed.
     * @param owner    The account granting the transient allowance.
     * @param spender  The contract invoked with that allowance.
     * @param selector The first four bytes of calldata, the function selector.
     * @param value    The transient allowance granted for the call.
    */
    event CalledWithTemporaryApprove(
        address indexed owner,
        address indexed spender,
        bytes4  indexed selector,
        uint256         value
    );

    /**
     * @dev Emitted when a transient allowance is granted.
     * @param owner   The account granting the transient allowance.
     * @param spender The spender receiving the transient allowance.
     * @param value   The transient allowance amount.
     */
    event TemporaryApproval(
        address indexed owner,
        address indexed spender,
        uint256         value
    );

    /**
     * @dev Emitted when a flash loan fee is paid.
     * @param payer    The borrower that repaid the loan and fee.
     * @param receiver The address receiving the fee.
     * @param value    The fee amount paid.
     */
    event FlashFeePaid(
        address indexed payer,
        address indexed receiver,
        uint256         value
    );

    /* ───────────────────────────── Constants ───────────────────────────── */
    /**
     * @dev Storage seed used for deriving transient allowance slots.
     */
    bytes32 private constant ERC20_TEMPORARY_APPROVAL_STORAGE = 0xea2d0e77a01400d0111492b1321103eed560d8fe44b9a7c2410407714583c400;

    /**
     * @dev EIP-2612 permit typehash used to build the EIP-712 struct hash.
     */
    bytes32 private constant _PERMIT_TYPEHASH      = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    /**
     * @dev Expected return value from IERC3156FlashBorrower.onFlashLoan.
     *      Used to validate the receiver callback in flash loans.
     */
    bytes32 private constant _FLASH_ON_LOAN_RETVAL = keccak256("ERC3156FlashBorrower.onFlashLoan");
    /**
     * @dev ERC-20 decimals.
     */
    uint8   private constant _decimals = 18;

    /** 
     * @dev Flash loan fee rate in parts-per-million.
     */
    uint256 private constant _FLASH_FEE_PPM = 1337;

    /* ───────────────────────────── Immutables ──────────────────────────── */
    /**
     * @dev Token name stored as ShortString immutable.
     */
    ShortString private immutable  _name;

    /**
     * @dev Token symbol stored as ShortString immutable.
     */
    ShortString private immutable _symbol;

    /**
     * @dev Immutable address that receives flash loan fees.
     */
    address     private immutable  _feeReceiver;

    /**
     * @dev Immutable cap on the total token supply.
     */
    uint256     private immutable  _cap;

    /* ────────────────────────────── Storage ────────────────────────────── */
    /**
     * @dev Storage fallback for the token name.
     */
    string private _nameFallback;

    /**
     * @dev Storage fallback for the token symbol.
     */
    string private _symbolFallback;

    /**
     * @dev Current total token supply.
     */
    uint256 private _totalSupply;

    /* ───────────────────────────── Transient ───────────────────────────── */
    /** 
     * @dev Transient reentrancy guard flag.
     */
    uint256 private transient  _flag;

    /* ───────────────────────────── Mappings ──────────────────────────────  */
    /**
     * @dev Mapping of account balances.
     */
    mapping(address account => uint256 balance)
            private _balances;
        
    /**
     * @dev Mapping of allowances per owner and spender.
     */
    mapping(address owner => mapping(address spender => uint256 allowance))
            private _allowances;

    /* ───────────────────────────── Modifiers ─────────────────────────────  */
    /**
     * @dev Transient reentrancy guard modifier.
     */
    modifier nonReentrant() {
        _nonReentrantEnter();
        _;
        _nonReentrantExit ();
    }

    /**
     * @dev Enter transient reentrancy flag.
     */
    function _nonReentrantEnter() private {
        require(_flag == 0, ReentrantCall());
        _flag = 1;
    }

    /**
     * @dev Exit transient reentrancy flag.
     */
    function _nonReentrantExit()  private {
        _flag = 0;
    }

    /* ───────────────────────────── ERC-20 implementation ─────────────────────── */
    /**
     * @dev Initializes the ERC-20 token.
     * @param name_         Token name   (ERC-20 metadata).
     * @param symbol_       Token symbol (ERC-20 metadata).
     * @param initialSupply Tokens minted to the deployer.
     * @param cap_          Maximum allowed total supply.
     * @param feeReceiver_  Recipient of flash loan fees.
     */
    constructor(
        string  memory name_,
        string  memory symbol_,
        uint256 initialSupply,
        uint256 cap_,
        address feeReceiver_
    ) EIP712(name_, "1") {
        require(bytes(name_)  .length != 0,  EmptyInitialName());
        require(bytes(symbol_).length != 0,  EmptyInitialSymbol());
        require(initialSupply         != 0,  ZeroInitialSupply());
        require(
            feeReceiver_     != address(0) &&
            feeReceiver_     != address(this), 
            InvalidFeeReceiver()
        );
        require(
            cap_ > initialSupply,
            InvalidInitialCap({
                initialSupply: initialSupply,
                cap:           cap_
            })
        );
        _name        = name_  .toShortStringWithFallback(_nameFallback);
        _symbol      = symbol_.toShortStringWithFallback(_symbolFallback);
        _cap         = cap_;
        _feeReceiver = feeReceiver_;
        _mint(_msgSender(), initialSupply);

    }

    /* ───────────────────────────── ERC-20 external ─────────────────────── */
    /**
     * @inheritdoc IERC20
     */
    function transfer(address to, uint256 amount)
        external
        override(IERC20)
        returns (bool)
    {
        address from = _msgSender();
        require(
            to != address(0),
            ERC20InvalidReceiver({ receiver: to })
        );

        if (amount == 0) {
            emit Transfer({
                from:  from,
                to:    to,
                value: 0
            });
            return true;
        }

        if (to == from) {
            uint256 fromBal = _balances[from];
            require(
                fromBal >= amount,
                ERC20InsufficientBalance({
                    sender:  from,
                    balance: fromBal,
                    needed:  amount
                })
            );

            emit Transfer({
                from:  from,
                to:    to,
                value: amount
            });
            return true;
        }
        _update(from, to, amount);
        return true;
    }

    /**
     * @inheritdoc IERC20
     * @dev Implements IERC7674 semantics using EIP-1153 transient storage.
     */
    function transferFrom(address from, address to, uint256 amount)
        external
        override(IERC20)
        returns (bool)
    {
        address spender = _msgSender();
        require(
            from != address(0),
            ERC20InvalidSender({ sender: from })
        );
        require(
            to != address(0),
            ERC20InvalidReceiver({ receiver: to })
        );

        if (amount == 0) {
            emit Transfer({
                from:  from,
                to:    to,
                value: 0
            });
            return true;
        }
        
        if (spender != from) {
            _spendWithTemporary(from, spender, amount);
        }
        _update(from, to, amount);
        return true;
    }

    /**
     * @inheritdoc IERC20
     */
    function approve(address spender, uint256 value)
        external
        override(IERC20)
        returns (bool)
    {
        _setAllowance(_msgSender(), spender, value);
        return true;
    }

    /*
     * @inheritdoc IERC7674
     * @dev Executes a low-level call to `spender` with `data`.
     */
    function temporaryApproveAndCall(
        address spender,
        uint256 value,
        bytes calldata data
    )
        external
        nonReentrant
        returns (bytes memory ret)
    {
        require(
            spender != address(0),
            ERC20InvalidSpender({ spender: spender })
        );
        address owner = _msgSender();
        _temporaryApprove(owner, spender, value);
        ret = Address.functionCall(spender, data);
        bytes4 selector = data.length >= 4 ? bytes4(data) : bytes4(0);
        emit CalledWithTemporaryApprove({
            owner:    owner,
            spender:  spender,
            value:    value,
            selector: selector
        });
        return ret;
    }

    /**
     * @inheritdoc IERC7674
     */
    function temporaryApprove(address spender, uint256 value)
        external
        override(IERC7674)
        returns (bool)
    {
        _temporaryApprove(_msgSender(), spender, value);
        return true;
    }

    /** 
     * @inheritdoc IERC20Permit
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    )
        external
        override(IERC20Permit)
    {
        require(
            T.timestamp() <= deadline,
            ERC2612ExpiredSignature({ deadline: deadline })
        );
        bytes32 structHash = keccak256(
            abi.encode(
                _PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                _useNonce(owner),
                deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, v, r, s);
        require(
            signer == owner,
            ERC2612InvalidSigner({
                signer: signer,
                owner:  owner
            })
        );
        _setAllowance(owner, spender, value);
    }

    /**
     * @inheritdoc IERC3156FlashLender
     * @dev Before returning from onFlashLoan the borrower must approve or 
     *      temporaryApprove value plus fee to this contract.
     */
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address        token,
        uint256        value,
        bytes calldata data
    )
        external
        override(IERC3156FlashLender) 
        nonReentrant 
        returns (bool) 
    {
        address self = address(this);
        require(
            token == self,
            ERC3156UnsupportedToken({ token: token })
        );
        require(
            value != 0, 
            ERC3156ZeroAmount({ amount: value })
        );
        uint256 maxLoan; unchecked { 
                maxLoan = _cap - _totalSupply; 
        }
        require(
            value <= maxLoan,
            ERC3156ExceededMaxLoan({ maxLoan: maxLoan })
        );
        uint256 fee = _flashFee(token, value);
        _mint(address(receiver), value);
        require(
            receiver.onFlashLoan(
                _msgSender(),
                token,
                value,
                fee,
                data
            ) == _FLASH_ON_LOAN_RETVAL,
            ERC3156InvalidReceiver({ receiver: address(receiver) })
        );
        address feeTo = _feeReceiver;
        uint256 repay = value + fee;
        _spendWithTemporary(address(receiver), self, repay);
        _update            (address(receiver), self, repay);
        _burn  (self, value);
        _update(self, feeTo, fee);
        emit FlashFeePaid({
            payer:    address(receiver),
            receiver: feeTo,
            value:    fee
        });
        return true;
    }

    /**
     * @notice Burns `amount` of tokens from the caller.
     * @param  amount The number of tokens to burn.
     */
    function burn(uint256 amount)
        external
        returns (bool)
    {
        address from = _msgSender();
        if (amount == 0) {
            emit Transfer({
                from:  from,
                to:    address(0),
                value: 0
            });
            return true;
        }
        _burn(from, amount);
        return true;
    }

    /**
     * @notice Burns `amount` tokens from `from` using the caller’s allowance.
     * @param from   The account from which tokens are deducted.
     * @param amount The number of tokens to burn.
     */
    function burnFrom(address from, uint256 amount)
        external
        returns (bool)
    {
        address spender = _msgSender();
        require(
            from != address(0),
            ERC20InvalidSender({ sender: from })
        );
        if (amount == 0) {
        emit Transfer({
            from:  from,
            to:    address(0),
            value: 0
        });
            return true;
        }
        if (spender != from) {
            _spendWithTemporary(from, spender, amount);
        }
        _burn(from, amount);
        return true;
    }

    /**
     * @notice Increases the allowance of `spender` granted by the caller by `added`.
     * @param spender The address whose allowance is increased.
     * @param added   The amount by which the allowance is increased.
     */
    function increaseAllowance(address spender, uint256 added)
        external
        returns (bool)
    {
        address owner = _msgSender();
        require(
            spender != address(0),
            ERC20InvalidSpender({ spender: spender })
        );
        mapping(address => uint256) storage a = _allowances[owner];
        uint256 current = a[spender];
        if (added == 0) {
            emit Approval({
                owner:   owner,
                spender: spender,
                value:   current
            });
            return true;
        }
        unchecked {
            uint256 updated = M.saturatingAdd(current, added);
            a[spender]      = updated;

            emit Approval({
                owner:   owner,
                spender: spender,
                value:   updated
            });
        }
        return true;
    }

    /**
     * @notice Decreases the allowance of `spender` granted by the caller by `subtracted`.
     * @param spender    The address whose allowance is decreased.
     * @param subtracted The amount by which the allowance is decreased.
     */
    function decreaseAllowance(address spender, uint256 subtracted)
        external
        returns (bool)
    {
        address owner = _msgSender();
        require(
            spender != address(0),
            ERC20InvalidSpender({ spender: spender })
        );
        mapping(address => uint256) storage a = _allowances[owner];
        uint256 current = a[spender];
        if (subtracted == 0) {
            emit Approval({
                owner:   owner,
                spender: spender,
                value:   current
            });
            return true;
        }
        require(
            current >= subtracted,
            ERC20InsufficientAllowance({
                spender:   spender,
                allowance: current,
                needed:    subtracted
            })
        );
        unchecked {
            uint256 updated = current - subtracted;
            a[spender]      = updated;

            emit Approval({
                owner:   owner,
                spender: spender,
                value:   updated
            });
        }
        return true;
    }

    /* ───────────────────────────── ERC-20 internal ─────────────────────── */
    /**
     * @dev Creates `amount` tokens and assigns them to `to`, increasing the total supply.
     *
     * Requirements:
     * - `to` must not be the zero address.
     * - Total supply after minting must not exceed {_cap}.
     *
     * Emits:
     * - {Transfer}
     */
    function _mint(address to, uint256 amount) 
        private
    {
        require(
            to != address(0),
            ERC20InvalidReceiver({ receiver: to })
        );
        uint256 newSupply = _totalSupply + amount;
        require(
            newSupply <= _cap,
            ERC20MintCapExceeded({
                newSupply: newSupply,
                cap:       _cap
            })
        );
        _totalSupply = newSupply;

        unchecked {
            _balances[to] += amount;
        }

        emit Transfer({
            from:  address(0),
            to:    to,
            value: amount
        });
    }

    /**
     * @dev Destroys `amount` tokens from `from`, decreasing the total supply.
     *
     * Requirements:
     * - `from` must have at least `amount` tokens.
     *
     * Emits: 
     * - {Transfer}
     */
    function _burn(address from, uint256 amount)
        private
    {
        uint256 fromBal = _balances[from];
        require(
            fromBal >= amount,
            ERC20InsufficientBalance({
                sender:  from,
                balance: fromBal,
                needed:  amount
            })
        );
        unchecked {
            _balances[from] = fromBal - amount;
            _totalSupply    -= amount;
        }
        emit Transfer({
            from:  from,
            to:    address(0),
            value: amount
        });
    }

    /**
     * @dev Updates balances to transfer `amount` from `from` to `to`.
     *
     * Requirements:
     * - `from` must have at least `amount` balance.
     *
     * Emits: 
     * - {Transfer}
     */
    function _update(address from, address to, uint256 amount) 
        private
    {
        uint256 fromBal = _balances[from];
        require(
            fromBal >= amount, 
            ERC20InsufficientBalance({
                sender:  from,
                balance: fromBal,
                needed:  amount
        }));
        unchecked {
            _balances[from] = fromBal - amount;
            _balances[to]  += amount;
        }
        emit Transfer({
            from:  from,
            to:    to,
            value: amount
        });
    }

    /**
     * @dev Sets allowance of `spender` over `owner`'s tokens to `value`.
     *
     * Requirements:
     * - `owner` and `spender` must not be the zero address.
     *
     * Emits: 
     * - {Approval}
     */
    function _setAllowance(address owner, address spender, uint256 value) 
        private 
    {
        require(
            owner != address(0),
            ERC20InvalidApprover({ approver: owner })
        );
        require(
            spender != address(0),
            ERC20InvalidSpender({ spender: spender })
        );
        uint256 prev = _allowances[owner][spender];

        if (prev != value) {
            _allowances[owner][spender] = value;
        }
        emit Approval({
            owner:   owner,
            spender: spender,
            value:   value
        });
    }

    /**
     * @dev Sets transient allowance of `spender` over `owner`'s tokens to `value`.
     *
     * Requirements:
     * - `owner` and `spender` must not be the zero address.
     *
     * Emits: 
     * - {TemporaryApproval}
     */
    function _temporaryApprove(address owner, address spender, uint256 value)
        private
    {
        require(
            spender != address(0),
            ERC20InvalidSpender({ spender: spender })
        );
        _temporaryAllowanceSlot(owner, spender).tstore(value);
        emit TemporaryApproval({
            owner:   owner,
            spender: spender,
            value:   value
        });
    }

    /**
     * @dev Deducts allowance for `spender` on behalf of `owner`.
     *
     * Resolution order:
     * - First consumes transient allowance from {temporaryApprove}.
     * - Then consumes persistent allowance from {_allowances}, if needed.
     *
     * Requirements:
     * - The combined transient and persistent allowance must be enough to cover `amount`.
     *   
     * Emits:
     * - {Approval} when persistent allowance is reduced.
     */
    function _spendWithTemporary(
        address owner,
        address spender,
        uint256 amount
    )
        private
    {
        TransientSlot.Uint256Slot slot = _temporaryAllowanceSlot(owner, spender);
        uint256 t = slot.tload();
        if (t == type(uint256).max) {
            return;
        }
        if (t >= amount) {
            unchecked {
                slot.tstore(t - amount);
            }
            return;
        }
        unchecked {
            amount -= t;
        }
        slot.tstore(0);
        uint256 allowed = _allowances[owner][spender];
        if (allowed != type(uint256).max) {
            require(
                allowed >= amount,
                ERC20InsufficientAllowance({
                    spender:   spender,
                    allowance: allowed,
                    needed:    amount
                })
            );
            unchecked {
                uint256 updated = allowed - amount;
                _allowances[owner][spender] = updated;
                emit Approval({
                    owner:   owner,
                    spender: spender,
                    value:   updated
                });
            }
        }
    }

    /**
     * @dev Computes the transient allowance slot for `owner` and `spender`.
     */
    function _temporaryAllowanceSlot(address owner, address spender)
        private
        pure
        returns (TransientSlot.Uint256Slot)
    {
        return ERC20_TEMPORARY_APPROVAL_STORAGE.deriveMapping(owner).deriveMapping(spender).asUint256();
    }

    /**
     * @dev Computes the flash loan fee for `value`, rounding up.
     */
    function _flashFee(address /*token*/, uint256 value)
        private
        pure
        returns (uint256)
    {
        return M.mulDiv(value, _FLASH_FEE_PPM, 1_000_000, M.Rounding.Ceil);
    }

    /* ───────────────────────────── ERC-20 viewers ─────────────────────── */
    /**
     * @inheritdoc IERC20Metadata
     */
    function name()
        external
        view
        override(IERC20Metadata)
        returns (string memory)
    {
        return _name.toStringWithFallback(_nameFallback);
    }

    /**
     * @inheritdoc IERC20Metadata
     */
    function symbol()
        external
        view
        override(IERC20Metadata)
        returns (string memory)
    {
        return _symbol.toStringWithFallback(_symbolFallback);
    }

    /**
     * @inheritdoc IERC20Metadata
     */
    function decimals()
        external
        pure
        override(IERC20Metadata)
        returns (uint8)
    {
        return _decimals;
    }

    /**
     * @inheritdoc IERC20
     */
    function totalSupply()
        external
        view
        override(IERC20)
        returns (uint256)
    {
        return _totalSupply;
    }

    /**
     * @dev Returns the cap on the token's total supply.
     */
    function cap()
        external
        view
        returns (uint256)
    {
        return _cap;
    }

    /**
     * @inheritdoc IERC20
     */
    function balanceOf(address account)
        external
        view
        override(IERC20)
        returns (uint256)
    {
        return _balances[account];
    }

    /**
     * @inheritdoc IERC20
     * @dev Implements IERC7674 semantics using EIP-1153 transient storage.
     * @return The sum of persistent and transient allowance, capped at max on overflow
     */
    function allowance(address owner, address spender)
        external
        view
        override(IERC20)
        returns (uint256)
    {
        (bool ok, uint256 sum) =
            M.tryAdd(_allowances[owner][spender], _temporaryAllowanceSlot(owner, spender).tload());
        return M.ternary(ok, sum, type(uint256).max);
    }

    /**
     * @dev Transient allowance of `spender` over `owner` for the current transaction.
     */
    function temporaryAllowance(address owner, address spender)
        external
        view
        returns (uint256)
    {
        return _temporaryAllowanceSlot(owner, spender).tload();
    }

    /** 
     * @dev Returns the receiver address of the flash fee.
     */
    function feeReceiver() 
        external
        view
        returns (address) 
    {
        return _feeReceiver;
    }

    /**
     * @inheritdoc IERC3156FlashLender
     */
    function flashFee(address token, uint256 value)
        external
        view
        override(IERC3156FlashLender)
        returns (uint256)
    {
        require(
            token == address(this),
            ERC3156UnsupportedToken({ token: token })
        );
        return _flashFee(token, value);
    }

    /**
     * @inheritdoc IERC3156FlashLender
     */
    function maxFlashLoan(address token)
        external
        view
        override(IERC3156FlashLender)
        returns (uint256)
    {
        if (token != address(this)) {
            return 0;
        }
        unchecked {
            return _cap - _totalSupply;
        }
    }

    /** 
     * @inheritdoc IERC20Permit
     */
    function DOMAIN_SEPARATOR()
        external
        view
        override(IERC20Permit)
        returns (bytes32)
    {
        return _domainSeparatorV4();
    }

    /** 
     * @inheritdoc IERC20Permit
     */
    function nonces(address owner)
        public
        view
        override(IERC20Permit, Nonces)
        returns (uint256)
    {
        return super.nonces(owner);
    }

    /* ───────────────────────────── Easter egg ───────────────────────────── */
    /**
     * @notice Grants the caller Anonyan-chan’s holy blessing.
     * Recommended to call via `cast`, terminal size: ~ 69x30.
     * 
     * Requirements:
     * - Function must be called with love.
     *
     * @param sender    The one to enlighten.
     * @return blessing The official blessing of Anonyan-chan.
     */
    function secretBlessing(address sender) 
        external 
        view
        returns (string[] memory blessing) 
    {
        string[] memory lines = new string[](28);
        lines[0]  = unicode"⣿⣿⣿⣿⣿⣿⣿⣤⡘⡍⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠋⡡⠊⠉⢀⠞⡻⠊⡐⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[1]  = unicode"⣿⣿⣿⣿⣿⣿⣿⡟⢿⠻⡀⠀⠀⠉⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⠀⠀⣠⠞⠃⠀⢀⡀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[2]  = unicode"⣿⣿⣿⣿⣿⣿⣿⡄⠀⢀⠳⡀⠀⠀⠀⠀⠀⠈⠙⢿⣿⣿⡿⠟⣻⠟⠉⠀⠀⠀⠀⠀⠀⠠⠟⠁⠀⠀⠀⣠⡞⠀⠀⡀⠠⢜⣡⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[3]  = unicode"⣿⣿⣿⣿⣿⣿⣿⡇⠂⣰⣧⠐⡄⠀⠀⠀⠀⠀⣐⣮⣤⠤⠀⠨⠴⣶⡶⡶⠤⣀⠀⠀⠀⠀⠀⠀⠑⠲⣿⣋⣭⣛⠁⠠⠒⢵⣏⡀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"; 
        lines[4]  = unicode"⣿⣿⣿⣿⣿⣿⣿⣹⣄⢘⣧⠀⢺⣆⠀⣠⠴⠛⠉⡱⠁⠀⠀⠀⠀⠀⠀⠀⠑⠢⡹⣦⡀⠀⠀⠀⠀⠀⠈⠻⡗⠀⠀⣀⣀⣒⡓⠧⡀⠀⢠⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[5]  = unicode"⣿⣿⣿⣿⣿⣿⣿⣿⡈⣙⡿⠂⢈⡿⠋⠀⠀⠀⠈⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠙⢝⣆⠑⡄⠀⠀⠀⠀⠘⢶⣀⣈⠉⣻⢿⡧⠀⠀⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[6]  = unicode"⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣿⣀⠞⠀⠀⡀⠀⠠⠂⠀⠀⠀⠀⠀⠱⠀⠀⠠⠀⠀⠀⠀⠀⠻⡱⣼⡄⠀⠀⠀⠀⠈⢗⠤⣅⣴⣟⣇⣠⠀⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[7]  = unicode"⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡿⠁⠀⠀⡰⠀⠀⡆⢰⠀⠀⠀⠀⠀⠀⢇⠀⠀⠑⡀⠀⠀⠀⠠⡘⢜⢿⡄⠀⢀⠀⠀⠈⢇⢨⣿⣿⠃⢀⣴⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"; 
        lines[8]  = unicode"⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⢠⢃⠀⣰⠀⠘⠀⠀⠀⠀⣇⠀⢸⣧⡀⠀⠘⢦⠀⠠⠀⠉⢌⠺⣷⠀⠈⡆⠀⠀⠘⣿⢟⡿⢶⣿⡟⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[9]  = unicode"⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⣤⠇⢠⡟⡆⠀⡄⠀⠀⠀⠘⡄⠀⢏⠓⢄⠀⠣⠳⣄⠑⢄⠀⠣⡹⣇⠀⢰⠀⠀⠀⢳⠈⣰⣿⣿⢅⠘⣱⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[10] = unicode"⣿⣿⣿⣿⣿⣿⠏⢠⠃⠀⠀⠀⢠⡟⠀⡾⠀⡇⠀⠂⠀⠀⠀⢳⠸⡄⠘⣄⣧⡦⡔⠒⠘⢯⡙⢍⠒⠚⢾⡀⠐⡆⠀⢡⠸⡮⠿⢫⡇⠘⡄⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[11] = unicode"⣿⣿⣿⣿⠟⠁⢠⠃⠀⠀⠀⠀⢸⠇⣸⠇⢠⢡⢀⢸⡀⠀⠀⠸⣧⢳⡠⢻⠀⠑⢜⣆⠘⠄⠑⢌⡳⡀⠀⠇⠀⣧⠀⢸⠀⣇⡰⠋⠀⠀⣷⠀⡀⠡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[12] = unicode"⣿⣿⠟⠁⢀⣴⡏⠀⡄⠀⠀⠀⢸⢀⣿⡀⠤⢼⡞⡄⣷⡘⣆⠀⠹⣍⣷⡀⢣⠀⠀⣙⣻⣦⣤⣤⣭⣛⣲⣤⠀⢹⠀⠀⠀⣍⣠⣤⠁⡰⢿⠀⠰⡀⠱⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[13] = unicode"⠋⢀⣠⣴⣿⣿⠁⠀⠁⠀⣸⠀⣾⠜⡏⠀⠀⠈⢿⡰⡘⣷⠘⣧⡀⠻⣿⣧⣀⣶⡿⢿⣿⣿⣿⣿⣿⡝⠻⣿⡶⠏⠀⠀⠀⢹⣿⣁⠜⡀⡿⣧⠀⡙⡄⠈⡢⡀⠀⠀⠀⠀⠀⠀⠀";
        lines[14] = unicode"⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⢿⠀⣿⠀⠃⠀⢀⣀⣨⠷⡑⢼⣧⡽⣷⣄⡀⢻⡠⡏⠀⠸⠏⢹⣿⣿⠙⡇⠀⣼⡇⠀⠀⠀⡆⣎⡙⢇⡰⢁⡇⣿⣧⣿⢮⠢⡀⠀⠑⠢⡀⠀⠀⠀⠀";
        lines[15] = unicode"⣿⣿⣿⣿⣿⡇⠀⠀⡇⠀⢸⡇⢻⠀⢐⣾⠟⣿⣿⣿⣗⠀⠈⠻⣆⠝⠣⢄⠈⠀⠀⠀⠰⣟⠹⢻⣿⠁⠀⠃⠁⠀⠀⢸⡇⣃⡁⢸⠁⣼⢧⢸⠙⡟⢷⣕⡌⠒⠤⣀⠀⠀⠀⠀⠀";
        lines[16] = unicode"⣿⣿⣿⣿⣿⡇⢸⠀⣧⠀⠸⣷⠘⣄⣾⠇⠀⠿⠛⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣈⣁⠉⣁⣀⣀⢀⡁⠀⠀⢸⡄⡏⣡⢟⣿⣿⠸⠀⠄⠸⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀";
        lines[17] = unicode"⣿⣿⢻⣿⣿⡇⢸⡆⢹⡄⠀⢹⣧⣻⡻⣇⠀⠀⢰⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠟⢁⠠⠀⢸⠇⠀⠀⠸⠃⡗⣡⣾⡏⢿⠀⡇⡇⠀⠑⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[18] = unicode"⣿⣿⣸⣿⣿⡇⢸⣷⡘⣷⡀⠈⣿⣿⣧⠈⠂⠀⠀⠉⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⣾⠀⠀⠀⣀⠀⣿⣿⢿⡇⢸⡄⠀⢩⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[19] = unicode"⣿⣿⢸⣿⣿⣿⠘⣿⣷⣹⣷⣄⠘⣎⢻⣇⠀⠔⢫⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡔⢸⠀⠀⠀⣿⢠⣿⡇⢸⡇⠀⢷⠀⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[20] = unicode"⣿⣿⣿⣿⣿⣿⣇⢿⣿⣿⣿⣿⡿⣏⠙⢿⠘⠒⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠊⢀⣼⠀⡄⢠⡏⢸⣿⣧⠘⣿⠀⠈⣇⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[21] = unicode"⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⡿⢁⣿⠀⠸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⣿⠀⠁⢸⡁⣼⣿⣿⠀⡟⡇⠀⠼⡀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[22] = unicode"⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣵⣿⢟⡄⠀⢛⠢⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠟⠁⢀⡏⠸⠀⣇⡆⣿⣿⣿⣇⣧⣿⡤⣶⣷⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[23] = unicode"⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣇⠀⠸⡀⢸⡏⠓⣦⣤⣀⣀⠀⠀⠀⠀⠀⣀⣤⣾⣿⠟⠁⣠⠐⠁⠃⡆⢠⣾⢱⣿⡏⢉⣀⣠⣴⢤⣤⣬⣁⡒⠢⠤⣄⣀⡀⠀⠀⠀⠀⠀";
        lines[24] = unicode"⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣼⣿⠀⠀⠃⠘⡇⢀⣿⢸⣿⣿⣿⣿⣷⣶⣿⣿⣿⠟⠁⡠⠊⠀⠀⠀⣷⠁⢸⣟⣸⠿⠿⢧⡅⢱⣧⠀⡅⡇⠇⢳⠈⠁⠢⡀⠁⠀⠀⠀⠀⠀";
        lines[25] = unicode"⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢃⣿⢸⡇⠀⠰⠀⣿⢸⣿⣿⣿⣿⣿⠟⢛⣩⣿⡏⠁⠔⠈⢀⣠⠄⠒⢸⡟⠀⣿⡇⡇⠀⠀⢸⠃⠘⣿⠀⡁⢁⢸⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀";
        lines[26] = unicode"⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⣼⣿⢸⣿⡀⠀⠀⢸⣿⣿⣿⡿⠋⠵⡽⠿⠛⠛⠋⠉⠉⠉⠁⡁⠀⠀⣿⡇⢠⣿⣹⠁⠀⠀⣿⠀⢰⢿⠀⠙⠘⢸⡀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠌";
        address beacon = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02; 
        bytes32 broot  = bytes32(0);
        assembly ("memory-safe") { 
            mstore(0x00, timestamp())
            if iszero(staticcall(gas(), beacon, 0x00, 0x20, 0x00, 0x20)) { mstore(0x00, 0) }
            broot := mload(0x00) 
        }
        uint256 rnd = uint256(
            keccak256(abi.encode(sender, "anonyan-blessing", block.prevrandao, broot))
        ); 
        (uint256 hi, ) = M.mul512(rnd, 101); uint256 power = hi;
        lines[27] = string.concat(
            "Blessing of Anonyan-chan received by: ",
            Strings.toChecksumHexString(sender), " with power ", Strings.toString(power), "%"
        );
        return lines;
    }

    /* ───────────────────────────── Fallbacks ───────────────────────────── */
    /**
     * @dev Rejects direct ETH transfers via receive.
     */
    receive() external payable {
        revert ReceiveDisable(_msgSender(), msg.value);
    }

    /**
     * @dev Rejects calls with ETH or data via fallback.
     */
    fallback() external payable {
        revert FallbackDisable(_msgSender(), msg.value, _msgData());
    }
}
