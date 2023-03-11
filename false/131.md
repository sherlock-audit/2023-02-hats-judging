Avci

high

# Admin who had hat level 0 is ignored already

## Summary
Admin who had hat level 0 is ignored already
## Vulnerability Detail
in the function isAdminOfHat from Hats.sol there is while checking if admin hat level is above the 0 but the reality is admin hat level starts at 0 and it ignores the admin in level 0 
```solidity
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
```
what doc says: 
`values at levels 0-5 as well as its own level. Since these values correspond to its admins, `
## Impact
the admin hat level 0 will be ignored at all by default 

## Code Snippet
```solidity
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
```
https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L856
## Tool used

Manual Review

## Recommendation
consider modifying contract to the ways it don't ignore the adding level 0 

or 
- levels start from one 
