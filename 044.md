obront

medium

# Safe threshold can be set above target threshold, causing transactions to revert

## Summary

If a `targetThreshold` is set below the safe's threshold, the `reconcileSignerCount()` function will fail to adjust the safe's threshold as it should, leading to a mismatch that causes all transactions to revert.

## Vulnerability Detail

It is possible and expected that the `targetThreshold` can be lowered, sometimes even lower than the current safe threshold.

In the `setTargetThreshold()` function, there is an automatic update to lower the safe threshold accordingly. However, in the event that the `signerCount < 2`, it will not occur. This could easily happen if, for example, the hat is temporarily toggled off.

But this should be fine! In this instance, when a new transaction is processed, `checkTransaction()` will be called, which calls `reconcileSignerCount()`. This should fix the problem by resetting the safe's threshold to be within the range of `minThreshold` to `targetThreshold`.

However, the logic to perform this update is faulty.
```solidity
uint256 currentThreshold = safe.getThreshold();
uint256 newThreshold;
uint256 target = targetThreshold; // save SLOADs

if (validSignerCount <= target && validSignerCount != currentThreshold) {
    newThreshold = validSignerCount;
} else if (validSignerCount > target && currentThreshold < target) {
    newThreshold = target;
}
if (newThreshold > 0) { ... update safe threshold ... }
```
As you can see, in the event that the `validSignerCount` is lower than the target threshold, we update the safe's threshold to `validSignerCount`. That is great.

In the event that `validSignerCount` is greater than threshold, we should be setting the safe's threshold to `targetThreshold`. However, this only happens in the `else if` clause, when `currentThreshold < target`.

As a result, in the situation where `target < current <= validSignerCount`, we will leave the current safe threshold as it is and not lower it. This results in a safe threshold that is greater than `targetThreshold`.

Here is a simple example:
- valid signers, target threshold, and safe's threshold are all 10
- the hat is toggled off
- we lower target threshold to 9
- the hat is toggled back on
- `if` block above (`validSignerCount <= target && validSignerCount != currentThreshold`) fails because `validSignerCount > target`
- `else if` block above (`validSignerCount > target && currentThreshold < target`) fails because `currentThreshold > target`
- as a result, `newThreshold == 0` and the safe isn't updated
- the safe's threshold remains at 10, which is greater than target threshold

In the `checkAfterExecution()` function that is run after each transaction, there is a check that the threshold is valid:
```solidity
if (safe.getThreshold() != _getCorrectThreshold()) {
    revert SignersCannotChangeThreshold();
}
```
The `_getCorrectThreshold()` function checks if the threshold is equal to the valid signer count, bounded by the `minThreshold` on the lower end, and the `targetThreshold` on the upper end:
```solidity
function _getCorrectThreshold() internal view returns (uint256 _threshold) {
    uint256 count = _countValidSigners(safe.getOwners());
    uint256 min = minThreshold;
    uint256 max = targetThreshold;
    if (count < min) _threshold = min;
    else if (count > max) _threshold = max;
    else _threshold = count;
}
```
Since our threshold is greater than `targetThreshold` this check will fail and all transactions will revert.

## Impact

A simple change to the `targetThreshold` fails to propagate through to the safe's threshold, which causes all transactions to revert. 

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L95-L114

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L183-L217

## Tool used

Manual Review

## Recommendation

Edit the if statement in `reconcileSignerCount()` to always lower to the `targetThreshold` if it exceeds it:
```diff
-if (validSignerCount <= target && validSignerCount != currentThreshold) {
+if (validSignerCount <= target) {
    newThreshold = validSignerCount;
-} else if (validSignerCount > target && currentThreshold < target) {
+} else {
    newThreshold = target;
}
-if (newThreshold > 0) { ... update safe threshold ... }
+if (newThreshold != currentThreshold) { ... update safe threshold ... }
```