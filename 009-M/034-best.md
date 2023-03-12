obront

medium

# Changing hat toggle address can lead to unexpected changes in status

## Summary

Changing the toggle address should not change the current status unless intended to. However, in the event that a contract's toggle status hasn't been synced to local state, this change can accidentally toggle the hat back on when it isn't intended.

## Vulnerability Detail

When an admin for a hat calls `changeHatToggle()`, the `toggle` address is updated to a new address they entered:
```solidity
function changeHatToggle(uint256 _hatId, address _newToggle) external {
    if (_newToggle == address(0)) revert ZeroAddress();

    _checkAdmin(_hatId);
    Hat storage hat = _hats[_hatId];

    if (!_isMutable(hat)) {
        revert Immutable();
    }

    hat.toggle = _newToggle;

    emit HatToggleChanged(_hatId, _newToggle);
}
```
Toggle addresses can be either EOAs (who must call `setHatStatus()` to change the local config) or contracts (who must implement the `getHatStatus()` function and return the value).

The challenge comes if a hat has a toggle address that is a contract. The contract changes its toggle value to `false` but is never checked (which would push the update to the local state). The admin thus expects that the hat is turned off.

Then, the toggle is changed to an EOA. One would expect that, until a change is made, the hat would remain in the same state, but in this case, the hat defaults back to its local storage state, which has not yet been updated and is therefore set to `true`.

Even in the event that the admin knows this and tries to immediately toggle the status back to `false`, it is possible for a malicious user to sandwich their transaction between the change to the EOA and the transaction to toggle the hat off, making use of a hat that should be off. This could have dramatic consequences when hats are used for purposes such as multisig signing.

## Impact

Hats may unexpectedly be toggled from `off` to `on` during toggle address transfer, reactivating hats that are intended to be turned off.

## Code Snippet

https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L623-L636

## Tool used

Manual Review

## Recommendation

The `changeHatToggle()` function needs to call `checkHatToggle()` before changing over to the new toggle address, to ensure that the latest status is synced up.