Allarious

medium

# [Medium][Outdated State] `_removeSigner` incorrectly updates `signerCount` and safe `threshold`

## Summary
`_removeSigner` can be called whenever a signer is no longer valid to remove an invalid signer. However, under certain situations, `removeSigner` incorrectly reduces the number of `signerCount` and sets the `threshold` incorrectly.

## Vulnerability Detail
`_removeSigner` uses the code snippet below to decide if the number of `signerCount` should be reduced:
```solidity
        if (validSignerCount == currentSignerCount) {
            newSignerCount = currentSignerCount;
        } else {
            newSignerCount = currentSignerCount - 1;
        }
```
If first clause is supposed to be activated when `validSignerCount` and `currentSignerCount` are still in sync, and we want to remove an invalid signer. The second clause is for when we need to identify a previously active signer which is inactive now and want to remove it. However, it does not take into account if a previously in-active signer became active. In the scenario described below, the `signerCount` would be updated incorrectly:

(1) Lets imagine there are 5 signers where 0, 1 and 2 are active while 3 and 4 are inactive, the current `signerCount = 3`
(2) In case number 3 regains its hat, it will become active again
(3) If we want to delete signer 4 from the owners' list, the `_removeSigner` function will go through the signers and find 4 valid signers, since there were previously 3 signers, `validSignerCount == currentSignerCount` would be false.
(4) In this case, while the number of `validSingerCount` increased, the `_removeSigner` reduces one.

## Impact
This can make the `signerCount` and safe `threshold` to update incorrectly which can cause further problems, such as incorrect number of signatures needed.

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L387

## Code Snippet
No code snippet provided

## Tool used

Manual Review

## Recommendation
Check if the number of `validSignerCount` decreased instead of checking equality:
```solidity
@line 387 HatsSignerGateBase
- if (validSignerCount == currentSignerCount) {
+ if (validSignerCount >= currentSignerCount) {
```
