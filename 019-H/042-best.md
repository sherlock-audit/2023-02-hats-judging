obront

high

# If another module adds a module, the safe will be bricked

## Summary

If a module is added by another module, it will bypass the `enableNewModule()` function that increments `enabledModuleCount`. This will throw off the module validation in `checkTransaction()` and `checkAfterExecution()` and could cause the safe to become permanently bricked.

## Vulnerability Detail

In order to ensure that signers cannot add new modules to the safe (thus giving them unlimited future governing power), the guard portion of the gate checks that the hash of the modules before the transaction is the same as the hash after.

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
You'll note that the "before" check uses `enabledModuleCount` and the "after" check uses `enabledModuleCount + 1`. The reason for this is that we want to be able to catch whether the user added a new module, which requires us taking a larger pagination to make sure we can view the additional module.

However, if we were to start with a number of modules larger than `enabledModuleCount`, the result would be that the "before" check would clip off the final modules, and the "after" check would include them, thus leading to different hashes.

This situation can only arise if a module is added that bypasses the `enableModule()` function. But this exact situation can happen if one of the other modules on the safe adds a module to the safe.

In this case, the modules on the safe will increase but `enabledModuleCount` will not. This will lead to the "before" and "after" checks returning different arrays each time, and therefore disallowing transactions. 

The only possible ways to fix this problem will be to have the other module remove the additional one they added. But, depending on the specific circumstances, this option may not be possible. For example, the module that performed the adding may not have the ability to remove modules.

## Impact

The safe can be permanently bricked, with the guard functions disallowing any transactions. All funds in the safe will remain permanently stuck.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L495-L498

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L521-L525

## Tool used

Manual Review

## Recommendation

The module guarding logic needs to be rethought. Given the large number of unbounded risks it opens up, I would recommend not allowing other modules on any safes that use this functionality.