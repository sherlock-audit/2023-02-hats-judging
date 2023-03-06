obront

high

# Signers can brick safe by adding unlimited additional signers while avoiding checks

## Summary

There are a number of checks in `checkAfterExecution()` to ensure that the signers cannot perform any illegal actions to exert too much control over the safe. However, there is no check to ensure that additional owners are not added to the safe. This could be done in a way that pushes the total over `maxSigners`, which will cause all future transactions to revert.

This means that signers can easily collude to freeze the contract, giving themselves the power to hold the protocol ransom to unfreeze the safe and all funds inside it.

## Vulnerability Detail

When new owners are added to the contract through the `claimSigner()` function, the total number of owners is compared to `maxSigners` to ensure it doesn't exceed it.

However, owners can also be added by a normal `execTransaction` function. In this case, there are very few checks (all of which could easily or accidentally be missed) to stop us from adding too many owners:

```solidity
if (safe.getThreshold() != _getCorrectThreshold()) {
    revert SignersCannotChangeThreshold();
}

function _getCorrectThreshold() internal view returns (uint256 _threshold) {
    uint256 count = _countValidSigners(safe.getOwners());
    uint256 min = minThreshold;
    uint256 max = targetThreshold;
    if (count < min) _threshold = min;
    else if (count > max) _threshold = max;
    else _threshold = count;
}
```
That means that either in the case that (a) the safe's threshold is already at `targetThreshold` or (b) the owners being added are currently toggled off or have eligibility turned off, this check will pass and the owners will be added.

Once they are added, all future transactions will fail. Each time a transaction is processed, `checkTransaction()` is called, which calls `reconcileSignerCount()`, which has the following check:
```solidity
if (validSignerCount > maxSigners) {
    revert MaxSignersReached();
}
```
This will revert as long as the new owners are now activated as valid signers.

In the worst case scenario, valid signers wearing an immutable hat are added as owners when the safe's threshold is already above `targetThreshold`. The check passes, but the new owners are already valid signers. There is no admin action that can revoke the validity of their hats, so the `reconcileSignerCount()` function will always revert, and therefore the safe is unusable.

Since `maxSigners` is immutable and can't be changed, the only solution is for the hat wearers to renounce their hats. Otherwise, the safe will remain unusable with all funds trapped inside.

## Impact

Signers can easily collude to freeze the contract, giving themselves the power to hold the protocol ransom to unfreeze the safe and all funds inside it.

In a less malicious case, signers might accidentally add too many owners and end up needing to manage the logistics of having users renounce their hats.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L507-L529

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L187-L189

## Tool used

Manual Review

## Recommendation

There should be a check in `checkAfterExecution()` that ensures that the number of owners on the safe has not changed throughout the execution.

It also may be recommended that the `maxSigners` value is adjustable by the contract owner.