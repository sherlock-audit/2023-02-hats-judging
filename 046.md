obront

high

# Other module can add owners to safe that push us above maxSigners, bricking safe

## Summary

If another module adds owners to the safe, these additions are not checked by our module or guard's logic. This can result in pushing us over `maxSigners`, which will cause all transactions to revert. In the case of an immutable hat, the only way to avoid the safe being locked permanently (with all funds frozen) may be to convince many hat wearers to renounce their hats.

## Vulnerability Detail

When new owners are added to the contract through the `claimSigner()` function, the total number of owners is compared to `maxSigners` to ensure it doesn't exceed it.

However, if there are other modules on the safe, they are able to add additional owners without these checks.

In the case of `HatsSignerGate.sol`, there is no need to call `claimSigner()` to "activate" these owners. They will automatically be valid as long as they are a wearer of the correct hat.

This could lead to an issue where many (more than `maxSigners`) wearers of an immutable hat are added to the safe as owners. Now, each time a transaction is processed, `checkTransaction()` is called, which calls `reconcileSignerCount()`, which has the following check:
```solidity
if (validSignerCount > maxSigners) {
    revert MaxSignersReached();
}
```
This will revert.

Worse, there is nothing the admin can do about it. If they don't have control over the eligibility address for the hat, they are not able to burn the hats or transfer them. 

The safe will be permanently bricked and unable to perform transactions unless the hat wearers agree to renounce their hats.

## Impact

The safe can be permanently bricked and unable to perform transactions unless the hat wearers agree to renounce their hats.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L187-L189

## Tool used

Manual Review

## Recommendation

If `validSignerCount > maxSigners`, there should be some mechanism to reduce the number of signers rather than reverting.

Alternatively, as suggested in another issue, to get rid of all the potential risks of having other modules able to make changes outside of your module's logic, we should create the limit that the HatsSignerGate module can only exist on a safe with no other modules.