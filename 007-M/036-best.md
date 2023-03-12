obront

medium

# targetThreshold can be set below minThreshold, violating important invariant

## Summary

There are protections in place to ensure that `minThreshold` is not set above `targetThreshold`, because the result is that the max threshold on the safe would be less than the minimum required. However, this check is not performed when `targetThreshold` is set, which results in the same situation.

## Vulnerability Detail

When the `minThreshold` is set on `HatsSignerGateBase.sol`, it performs an important check that `minThreshold <= targetThreshold`:

```solidity
function _setMinThreshold(uint256 _minThreshold) internal {
    if (_minThreshold > maxSigners || _minThreshold > targetThreshold) {
        revert InvalidMinThreshold();
    }

    minThreshold = _minThreshold;
}
```

However, when `targetThreshold` is set, there is no equivalent check that it remains above `minThreshold`:

```solidity
function _setTargetThreshold(uint256 _targetThreshold) internal {
    if (_targetThreshold > maxSigners) {
        revert InvalidTargetThreshold();
    }

    targetThreshold = _targetThreshold;
}
```

This is a major problem, because if it is set lower than `minThreshold`, `reconcileSignerCount()` will set the safe's threshold to be this value, which is lower than the minimum, and will cause all tranasctions to fail.

## Impact

Settings that are intended to be guarded are not, which can lead to parameters being set in such a way that all transactions fail.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L95-L114

## Tool used

Manual Review

## Recommendation

Perform a check in `_setTargetThreshold()` that it is greater than or equal to `minThreshold`:

```diff
function _setTargetThreshold(uint256 _targetThreshold) internal {
+   if (_targetThreshold < minThreshold) {
+     revert InvalidTargetThreshold();
+   }
    if (_targetThreshold > maxSigners) {
        revert InvalidTargetThreshold();
    }

    targetThreshold = _targetThreshold;
}
```