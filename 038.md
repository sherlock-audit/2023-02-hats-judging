obront

medium

# Swap Signer fails if final owner is invalid due to off by one error in loop

## Summary

New users attempting to call `claimSigner()` when there is already a full slate of owners are supposed to kick any invalid owners off the safe in order to swap in and take their place. However, the loop that checks this has an off-by-one error that misses checking the final owner.

## Vulnerability Detail

When `claimSigner()` is called, it adds the `msg.sender` as a signer, as long as there aren't already too many owners on the safe.

However, in the case that there are already the maximum number of owners on the safe, it performs a check whether any of them are invalid. If they are, it swaps out the invalid owner for the new owner.

```solidity
if (ownerCount >= maxSigs) {
    bool swapped = _swapSigner(owners, ownerCount, maxSigs, currentSignerCount, msg.sender);
    if (!swapped) {
        // if there are no invalid owners, we can't add a new signer, so we revert
        revert NoInvalidSignersToReplace();
    }
}
```

```solidity
function _swapSigner(
    address[] memory _owners,
    uint256 _ownerCount,
    uint256 _maxSigners,
    uint256 _currentSignerCount,
    address _signer
) internal returns (bool success) {
    address ownerToCheck;
    bytes memory data;

    for (uint256 i; i < _ownerCount - 1;) {
        ownerToCheck = _owners[i];

        if (!isValidSigner(ownerToCheck)) {
            // prep the swap
            data = abi.encodeWithSignature(
                "swapOwner(address,address,address)",
                _findPrevOwner(_owners, ownerToCheck), // prevOwner
                ownerToCheck, // oldOwner
                _signer // newOwner
            );

            // execute the swap, reverting if it fails for some reason
            success = safe.execTransactionFromModule(
                address(safe), // to
                0, // value
                data, // data
                Enum.Operation.Call // operation
            );

            if (!success) {
                revert FailedExecRemoveSigner();
            }

            if (_currentSignerCount < _maxSigners) ++signerCount;
            break;
        }
        unchecked {
            ++i;
        }
    }
}
```
This function is intended to iterate through all the owners, check if any is no longer valid, and — if that's the case — swap it for the new one.

However, in the case that all owners are valid except for the final one, it will miss the swap and reject the new owner. 

This is because there is an off by one error in the loop, where it iterates through `for (uint256 i; i < _ownerCount - 1;)...`

This only iterates through all the owners up until the final one, and will miss the check for the validity and possible swap of the final owner.

## Impact

When only the final owner is invalid, new users will not be able to claim their role as signer, even through they should.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGate.sol#L57-L69

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L308-L350

## Tool used

Manual Review

## Recommendation

Perform the loop with `ownerCount` instead of `ownerCount - 1` to check all owners:

```diff
- for (uint256 i; i < _ownerCount - 1;) {
+ for (uint256 i; i < _ownerCount ;) {
     ownerToCheck = _owners[i];
    ...
}
```