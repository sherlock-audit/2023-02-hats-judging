GimelSec

medium

# `removeSigner()` would fail if `currentSignerCount < validSignerCount`.

## Summary

`removeSigner()` would fail if `currentSignerCount < validSignerCount`, nobody could remove invalid signers.

## Vulnerability Detail

Suppose we have a Safe with a signer gate:
* owners.length: 10

At the beginning, only 3 owners wore a valid signer hat (`signerCount` is 3). Then the admin mint 3 hats for other owners (`_countValidSigners(owners)` will be 6), so only 4 owners are invalid.
* currentSignerCount (aka `signerCount`): 3
* validSignerCount (aka `_countValidSigners(owners)`): 6

If users call `removeSigner()` to remove invalid owners, the `signerCount` will update to `newSignerCount = currentSignerCount - 1`, which is `3 - 1 = 2`.
But the 4th call of `removeSigner()` will fail because `currentSignerCount` is underflow in [L390](https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L390).

The solution is that users should call `reconcileSignerCount()` to update `signerCount` before calling `removeSigner()`. But the solution would result in bad UX, that users don't know they should call `reconcileSignerCount()` first and get confused.

On the other hand, it's possible that `reconcileSignerCount()` may be blocked. See more details in GimelSec issue `reconcileSignerCount() would be blocked if validSignerCount > maxSigners, Safe would not be able to execute any transactions, all assets would be locked`.

Also, `claimSigner()` could call `_swapSigner()` to remove invalid signers, but if `ownerCount < maxSigs`, it will only call `_grantSigner`, those invalid owners are still in the Safe.

## Impact

The `removeSigner()` would fail, nobody could call the function to remove invalid signers.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L390

## Tool used

Manual Review

## Recommendation

Use `validSignerCount - 1` in L390:

```solidity
                newSignerCount = validSignerCount - 1;
```
