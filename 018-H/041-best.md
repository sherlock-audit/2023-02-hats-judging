obront

high

# Signers can bypass checks to add new modules to a safe by abusing reentrancy

## Summary

The `checkAfterExecution()` function has checks to ensure that new modules cannot be added by signers. This is a crucial check, because adding a new module could give them unlimited power to make any changes (with no guards in place) in the future. However, by abusing reentrancy, the parameters used by the check can be changed so that this crucial restriction is violated.

## Vulnerability Detail

The `checkAfterExecution()` is intended to uphold important invariants after each signer transaction is completed. This is intended to restrict certain dangerous signer behaviors, the most important of which is adding new modules. This was an issue caught in the previous audit and fixed by comparing the hash of the modules before execution to the has of the modules after.

Before:
```solidity
(address[] memory modules,) = safe.getModulesPaginated(SENTINEL_OWNERS, enabledModuleCount);
_existingModulesHash = keccak256(abi.encode(modules));
```

After:
```solidity
(address[] memory modules,) = safe.getModulesPaginated(SENTINEL_OWNERS, enabledModuleCount + 1);
if (keccak256(abi.encode(modules)) != _existingModulesHash) {
    revert SignersCannotChangeModules();
}
```
This is further emphasized in the comments, where it is specified:

> /// @notice Post-flight check to prevent `safe` signers from removing this contract guard, changing any modules, or changing the threshold

### Why Restricting Modules is Important

Modules are the most important thing to check. This is because modules have unlimited power not only to execute transactions but to skip checks in the future. Creating an arbitrary new module is so bad that it is equivalent to the other two issues together: getting complete control over the safe (as if threshold was set to 1) and removing the guard (because they aren't checked in module transactions).

However, this important restriction can be violated by abusing reentrancy into this function.

### Reentrancy Disfunction

To see how this is possible, we first have to take a quick detour regarding reentrancy. It appears that the protocol is attempting to guard against reentrancy with the `guardEntries` variable. It is incremented in `checkTransaction()` (before a transaction is executed) and decremented in `checkAfterExecution()` (after the transaction has completed).

The only protection it provides is in its risk of underflowing, explained in the comments as:

> // leave checked to catch underflows triggered by re-erntry attempts

However, any attempt to reenter and send an additional transaction midstream of another transaction would first trigger the `checkTransaction()` function. This would increment `_guardEntries` and would lead to it not underflowing.

In order for this system to work correctly, the `checkTransaction()` function should simply set `_guardEntries = 1`. This would result in an underflow with the second decrement. But, as it is currently designed, there is no reentrancy protection.

### Using Reentrancy to Bypass Module Check

Remember that the module invariant is upheld by taking a snapshot of the hash of the modules in `checkTransaction()` and saving it in the `_existingModulesHash` variable.

However, imagine the following set of transactions:
- Signers send a transaction via the safe, and modules are snapshotted to `_existingModulesHash`
- The transaction uses the Multicall functionality of the safe, and performs the following actions:
- First, it adds the malicious module to the safe
- Then, it calls `execTransaction()` on itself with any another transaction
- The second call will call `checkTransaction()`
- This will update `_existingModulesHash` to the new list of modules, including the malicious one
- The second call will execute, which doesn't matter (could just be an empty transaction)
- After the transaction, `checkAfterExecution()` will be called, and the modules will match
- After the full transaction is complete, `checkAfterExecution()` will be called for the first transaction, but since `_existingModulesHash` will be overwritten, the module check will pass

## Impact

Any number of signers who are above the threshold will be able to give themselves unlimited access over the safe with no restriction going forward.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L495-L498

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L522-L525

## Tool used

Manual Review

## Recommendation

Use a more typical reentrancy guard format, such as checking to ensure `_guardEntries == 0` at the top of `checkTransaction()` or simply setting `_guardEntries = 1` in `checkTransaction()` instead of incrementing it.