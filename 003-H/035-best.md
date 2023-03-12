obront

high

# Unlinked tophat retains linkedTreeRequests, can be rugged

## Summary

When a tophat is unlinked from its admin, it is intended to regain its status as a tophat that is fully self-sovereign. However, because the `linkedTreeRequests` value isn't deleted, an independent tophat could still be vulnerable to "takeover" from another admin and could lose its sovereignty.

## Vulnerability Detail

For a tophat to get linked to a new tree, it calls `requestLinkTopHatToTree()` function:
```solidity
function requestLinkTopHatToTree(uint32 _topHatDomain, uint256 _requestedAdminHat) external {
    uint256 fullTopHatId = uint256(_topHatDomain) << 224; // (256 - TOPHAT_ADDRESS_SPACE);

    _checkAdmin(fullTopHatId);

    linkedTreeRequests[_topHatDomain] = _requestedAdminHat;
    emit TopHatLinkRequested(_topHatDomain, _requestedAdminHat);
}
```
This creates a "request" to link to a given admin, which can later be approved by the admin in question:
```solidity
function approveLinkTopHatToTree(uint32 _topHatDomain, uint256 _newAdminHat) external {
    // for everything but the last hat level, check the admin of `_newAdminHat`'s theoretical child hat, since either wearer or admin of `_newAdminHat` can approve
    if (getHatLevel(_newAdminHat) < MAX_LEVELS) {
        _checkAdmin(buildHatId(_newAdminHat, 1));
    } else {
        // the above buildHatId trick doesn't work for the last hat level, so we need to explicitly check both admin and wearer in this case
        _checkAdminOrWearer(_newAdminHat);
    }

    // Linkages must be initiated by a request
    if (_newAdminHat != linkedTreeRequests[_topHatDomain]) revert LinkageNotRequested();

    // remove the request -- ensures all linkages are initialized by unique requests,
    // except for relinks (see `relinkTopHatWithinTree`)
    delete linkedTreeRequests[_topHatDomain];

    // execute the link. Replaces existing link, if any.
    _linkTopHatToTree(_topHatDomain, _newAdminHat);
}
```
This function shows that if there is a pending `linkedTreeRequests`, then the admin can use that to link the tophat into their tree and claim authority over it.

When a tophat is unlinked, it is expected to regain its sovereignty:
```solidity
function unlinkTopHatFromTree(uint32 _topHatDomain) external {
    uint256 fullTopHatId = uint256(_topHatDomain) << 224; // (256 - TOPHAT_ADDRESS_SPACE);
    _checkAdmin(fullTopHatId);

    delete linkedTreeAdmins[_topHatDomain];
    emit TopHatLinked(_topHatDomain, 0);
}
```
However, this function does not delete `linkedTreeRequests`.

Therefore, the following set of actions is possible:
- TopHat is linked to Admin A
- Admin A agrees to unlink the tophat
- Admin A calls `requestLinkTopHatToTree` with any address as the admin
- This call succeeds because Admin A is currently an admin for TopHat
- Admin A unlinks TopHat as promised
- In the future, the address chosen can call `approveLinkTopHatToTree` and take over admin controls for the TopHat without the TopHat's permission

## Impact

Tophats that expect to be fully self-sovereign and without any oversight can be surprisingly claimed by another admin, because settings from a previous admin remain through unlinking.

## Code Snippet

https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L688-L732

## Tool used

Manual Review

## Recommendation

In `unlinkTopHatFromTree()`, the `linkedTreeRequests` should be deleted:

```diff
function unlinkTopHatFromTree(uint32 _topHatDomain) external {
    uint256 fullTopHatId = uint256(_topHatDomain) << 224; // (256 - TOPHAT_ADDRESS_SPACE);
    _checkAdmin(fullTopHatId);

    delete linkedTreeAdmins[_topHatDomain];
+   delete linkedTreeRequests[_topHatDomain];
    emit TopHatLinked(_topHatDomain, 0);
}
```