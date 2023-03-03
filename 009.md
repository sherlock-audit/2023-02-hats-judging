roguereddwarf

medium

# Hats.sol: linkedTreeRequests entry should be deleted when unlinking

## Summary
A top hat can be linked to a hat of another tree.

In order to do this, an admin of the top hat can call `requestLinkTopHatToTree`:

```solidity
    function requestLinkTopHatToTree(uint32 _topHatDomain, uint256 _requestedAdminHat) external {
        uint256 fullTopHatId = uint256(_topHatDomain) << 224; // (256 - TOPHAT_ADDRESS_SPACE);


        // The wearer of an unlinked tophat is also the admin of same; once a tophat is linked, its wearer is no longer its admin
        _checkAdmin(fullTopHatId);


        linkedTreeRequests[_topHatDomain] = _requestedAdminHat;
        emit TopHatLinkRequested(_topHatDomain, _requestedAdminHat);
    }
```

As you can see this saves the `_requestedAdminHat` to the `linkedTreeRequests` mapping such that later on an admin (or wearer) of the `_requestedAdminHat` can accept the linking.

## Vulnerability Detail
So far so good. The issue comes when a top hat is unlinked again. Unlinking does not clear the `linkedTreeRequests` entry.

So think of the following scenario:

1. Top Hat A is linked to Tree B.

2. An admin from Tree B can now request Top Hat A to be linked to Tree C. (`linkedTreeRequests[A]=C`)

3. This entry in the `linkedTreeRequests` mapping is persistent even when Top Hat A is unlinked from Tree B. So an admin from Tree C can now accept the linking request.

This should not be possible because by unlinking Top Hat A from Tree B, Tree B gives up admin access to Top Hat A. So the linking request should be deleted as well. The fact that after unlinking, Tree A should be fully autonomous and not affected by Tree B anymore and that this behavior is not intended has been confirmed to me by the sponsor.

The fact that this is unintended can also be observed by looking at the `_linkTopHatToTree` function which only allows relinking within the same tree:

[Link](https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L764-L769)
```solidity
        // disallow relinking to separate tree
        if (linkedTreeAdmins[_topHatDomain] > 0) {
            if (!sameTippyTopHatDomain(_topHatDomain, _newAdminHat)) {
                revert CrossTreeLinkage();
            }
        }
```

This can be bypassed using the behavior described in this report.

## Impact
Unintended linking can occur that was initiated by a hat that should not have permission to do it.

## Code Snippet
https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L688-L696

https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L703-L721

## Tool used
Manual Review

## Recommendation
I propose the following change to the `unlinkTopHatFromTree` function:
```diff
diff --git a/src/Hats.sol b/src/Hats.sol
index ae41a54..9f1396a 100644
--- a/src/Hats.sol
+++ b/src/Hats.sol
@@ -728,6 +728,7 @@ contract Hats is IHats, ERC1155, HatsIdUtilities {
         _checkAdmin(fullTopHatId);
 
         delete linkedTreeAdmins[_topHatDomain];
+        delete linkedTreeRequests[_topHatDomain];
         emit TopHatLinked(_topHatDomain, 0);
     }
```