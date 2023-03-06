unforgiven

medium

# Unbound recursive function call can use unlimited gas and break hats operation

## Summary
some of the functions in the Hats and HatsIdUtilities contracts has recursive logics without limiting the number of iteration, this can cause unlimited gas usage if hat trees has huge depth and it won't be possible to call the contracts functions. functions `getImageURIForHat()`, `isAdminOfHat()`, `getTippyTopHatDomain()` and `noCircularLinkage()` would revert and because most of the logics callings those functions so contract would be in broken state for those hats.

## Vulnerability Detail
This is function `isAdminOfHat()` code:
```solidity
    function isAdminOfHat(address _user, uint256 _hatId) public view returns (bool isAdmin) {
        uint256 linkedTreeAdmin;
        uint32 adminLocalHatLevel;
        if (isLocalTopHat(_hatId)) {
            linkedTreeAdmin = linkedTreeAdmins[getTopHatDomain(_hatId)];
            if (linkedTreeAdmin == 0) {
                // tree is not linked
                return isAdmin = isWearerOfHat(_user, _hatId);
            } else {
                // tree is linked
                if (isWearerOfHat(_user, linkedTreeAdmin)) {
                    return isAdmin = true;
                } // user wears the treeAdmin
                else {
                    adminLocalHatLevel = getLocalHatLevel(linkedTreeAdmin);
                    _hatId = linkedTreeAdmin;
                }
            }
        } else {
            // if we get here, _hatId is not a tophat of any kind
            // get the local tree level of _hatId's admin
            adminLocalHatLevel = getLocalHatLevel(_hatId) - 1;
        }

        // search up _hatId's local address space for an admin hat that the _user wears
        while (adminLocalHatLevel > 0) {
            if (isWearerOfHat(_user, getAdminAtLocalLevel(_hatId, adminLocalHatLevel))) {
                return isAdmin = true;
            }
            // should not underflow given stopping condition > 0
            unchecked {
                --adminLocalHatLevel;
            }
        }

        // if we get here, we've reached the top of _hatId's local tree, ie the local tophat
        // check if the user wears the local tophat
        if (isWearerOfHat(_user, getAdminAtLocalLevel(_hatId, 0))) return isAdmin = true;

        // if not, we check if it's linked to another tree
        linkedTreeAdmin = linkedTreeAdmins[getTopHatDomain(_hatId)];
        if (linkedTreeAdmin == 0) {
            // tree is not linked
            // we've already learned that user doesn't wear the local tophat, so there's nothing else to check; we return false
            return isAdmin = false;
        } else {
            // tree is linked
            // check if user is wearer of linkedTreeAdmin
            if (isWearerOfHat(_user, linkedTreeAdmin)) return true;
            // if not, recurse to traverse the parent tree for a hat that the user wears
            isAdmin = isAdminOfHat(_user, linkedTreeAdmin);
        }
    }
```
As you can see this function calls itself recursively to check that if user is wearer of the one of the upper link hats of the hat or not. if the chain(depth) of the hats in the tree become very long then this function would revert because of the gas usage and the gas usage would be high enough so it won't be possible to call this function in a transaction. functions `getImageURIForHat()`, `getTippyTopHatDomain()` and `noCircularLinkage()` has similar issues and the gas usage is depend on the tree depth. the issue can happen suddenly for hats if the top level topHat decide to add link, for example:
1. Hat1 is linked to chain of the hats that has 1000 "root hat" and the topHat (tippy hat) is TIPHat1.
2. Hat2 is linked to chain of the hats that has 1000 "root hat" and the topHat (tippy hat) is TIPHat2.
3. admin of the TIPHat1 decides to link it to the Hat2 and all and after performing that the total depth of the tree would increase to 2000 and transactions would cost double time gas.

## Impact
it won't be possible to perform actions for those hats and funds can be lost because of it.

## Code Snippet
https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L831-L883

https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L1022-L1067

https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/HatsIdUtilities.sol#L194-L200

https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/HatsIdUtilities.sol#L184-L188


## Tool used
Manual Review

## Recommendation
code should check and make sure that hat levels has a maximum level and doesn't allow actions when this level breaches. (keep depth of each tophat's tree and update it when actions happens and won't allow actions if they increase depth  higher than the threshold)