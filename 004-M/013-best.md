carrot

medium

# `claimSigner` can unexpectedly revert

## Summary
Function `claimsigner` can revert even in conditions where it is supposed to let the user register as a signer.
## Vulnerability Detail
The function`claimSigner` checks the `currentSignerCount` against `maxSigs`. However this value can be outdated, leading to unexpected reverts.
https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/MultiHatsSignerGate.sol#L45-L47
```solidity
        if (currentSignerCount >= maxSigs) {
            revert MaxSignersReached();
        }
```
This situation can happen in multiple ways:
1. Signer count = max Sig. A signer is banned with badStanding. When a new signer comes to claim, their transaction gets reverted due to old value of signer count
2. Signer count = max Sig. A hatId gets toggled, opening up new signer spots for other signers. Transaction gets reverted for the same reason.

This would require the user to call `reconcileSignerCount` which would update the values. However this leads to bad user experience and excess gas usage, since the revert message can also be mis-interpreted to mean the maximum number of signer spots are already full. This would also lead to the added consequence that whenever a user's `claimSigner` call gets rejected due to the slots being legitimately filled, they would still try to reconcile the count wasting gas.
## Impact
Unexpected reverts, bad user experience
## Code Snippet
https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/MultiHatsSignerGate.sol#L45-L47
## Tool used

Manual Review

## Recommendation
Can be mitigated in multiple ways
1. call `reconcileSignerCount` from within claimSigner
2. check `maxSigs` against `_countValidSigners`