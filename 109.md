unforgiven

medium

# Hats contract functions doesn't check that all upper level hats exists and it would be possible to link a hat to non-existing hats

## Summary
functions createHat(), requestLinkTopHatToTree(), approveLinkTopHatToTree() and _linkTopHatToTree() are used to link hats to another hats but code doesn't check that all the upper level hats are exists and it's possible to link a hat to another hats that middle level hats are not created yet. code should check that for all upper level hats the maxSupply is higher than 0.

## Vulnerability Detail
This is `createHat()` code:
```solidity
    function createHat(
        uint256 _admin,
        string calldata _details,
        uint32 _maxSupply,
        address _eligibility,
        address _toggle,
        bool _mutable,
        string calldata _imageURI
    ) public returns (uint256 newHatId) {
        if (uint16(_admin) > 0) {
            revert MaxLevelsReached();
        }

        if (_eligibility == address(0)) revert ZeroAddress();
        if (_toggle == address(0)) revert ZeroAddress();

        newHatId = getNextId(_admin);

        // to create a hat, you must be wearing one of its admin hats
        _checkAdmin(newHatId);

        // create the new hat
        _createHat(newHatId, _details, _maxSupply, _eligibility, _toggle, _mutable, _imageURI);

        // increment _admin.lastHatId
        // use the overflow check to constrain to correct number of hats per level
        ++_hats[_admin].lastHatId;
    }
```
As you can see it calls `_checkAdmin()` and if it was true it creates new hat under admin hat id. This is `_checkAdmin()` code:
```solidity
    function _checkAdmin(uint256 _hatId) internal view {
        if (!isAdminOfHat(msg.sender, _hatId)) {
            revert NotAdmin(msg.sender, _hatId);
        }
    }
```
it calls `isAdminOfHat()` which is:
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
As you can see code doesn't check that the middle level hats exists (maxSupply>0) and if in any level of upper level hats the 
user wears a hat then code would return true. so a malicious admin can perform this:
1. User1 is admin of the topHat X. the ID is : XX00000000000000000000.
2. now User1 can call `createHat(XX000000001100)` and create a new hat with ID XX00000000001101.
3. while the middle level Hats in the XX0000000001101 doesn't exists (the ID is 0) but code would create the new hat.

other functions requestLinkTopHatToTree(), approveLinkTopHatToTree() and _linkTopHatToTree()  has similar problem and code allows to link a Hat to ID XX000000001100 and even so the middle level hats doesn't exists because the topHat XX exists code would allow it. linking hat to non-existing hats can cause issues if those ids created in the future with unknown paramters.

## Impact
it's possible to link hats to to trees that some middle level hats doesn't exist yet and it is also possible to create hats for admins that some middle level hats doesn't exists. (it's possible to create hat with id XX0000000001101 if topHat XX exists). This can cause logical or operational issues for the created hats and also it would be possible to create the upper level hats later with arbitrary parameters later. for example external user would think that the whole chain of the upper level hats are immutable but it would be possible to insert new upper level hat later that is mutable.

## Code Snippet
https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L831-L883

https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L761-L773

## Tool used
Manual Review

## Recommendation
check that middle level hats exists when creating new hats or linking hat to another hat.