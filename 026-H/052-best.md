obront

high

# Signers can bypass checks and change threshold within a transaction

## Summary

The `checkAfterExecution()` function has checks to ensure that the safe's threshold isn't changed by a transaction executed by signers. However, the parameters used by the check can be changed midflight so that this crucial restriction is violated.

## Vulnerability Detail

The `checkAfterExecution()` is intended to uphold important invariants after each signer transaction is completed. This is intended to restrict certain dangerous signer behaviors. From the docs:

> /// @notice Post-flight check to prevent `safe` signers from removing this contract guard, changing any modules, or changing the threshold

However, the restriction that the signers cannot change the threshold can be violated.

To see how this is possible, let's check how this invariant is upheld. The following check is performed within the function:
```solidity
if (safe.getThreshold() != _getCorrectThreshold()) {
    revert SignersCannotChangeThreshold();
}
```
If we look up `_getCorrectThreshold()`, we see the following:
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
As we can see, this means that the safe's threshold after the transaction must equal the valid signers, bounded by the `minThreshold` and `maxThreshold`.

However, this check does not ensure that the value returned by `_getCorrectThreshold()` is the same before and after the transaction. As a result, as long as the number of owners is also changed in the transaction, the condition can be upheld.

To illustrate, let's look at an example:
- Before the transaction, there are 8 owners on the vault, all signers. targetThreshold == 10 and minThreshold == 2, so the safe's threshold is 8 and everything is good.
- The transaction calls `removeOwner()`, removing an owner from the safe and adjusting the threshold down to 7.
- After the transaction, there will be 7 owners on the vault, all signers, the safe's threshold will be 7, and the check will pass.

This simple example focuses on using `removeOwner()` once to decrease the threshold. However, it is also possible to use the safe's multicall functionality to call `removeOwner()` multiple times, changing the threshold more dramatically.

## Impact

Signers can change the threshold of the vault, giving themselves increased control over future transactions and breaking an important trust assumption of the protocol.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L517-L519

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L533-L540

https://github.com/Hats-Protocol/safe-contracts/blob/c36bcab46578a442862d043e12a83fec41143dec/contracts/base/OwnerManager.sol#L70-L86

## Tool used

Manual Review

## Recommendation

Save the safe's current threshold in `checkTransaction()` before the transaction has executed, and compare the value after the transaction to that value from storage.