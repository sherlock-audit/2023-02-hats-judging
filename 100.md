unforgiven

high

# bypass maxsupply limit(and other impacts) by performing reentrancy in createHat() function

## Summary
function createHat() is used for creating new hats and it uses function `_checkAdmin()` to make caller is admin of the newHatId. function `_checkAdmin()` makes external calls to upper level hats toggle and eligibility contracts. because function `createHat()` doesn't protect itself from reentrancy(no reentrancy guard and no check-effect-interaction pattern) it's possible to perform reentrancy during `createHat()` and create the same id again with bigger maxSupply and mint the new hats and then we would have a hat that wearers are bigger than maxSupply. also code would have multiple emits for the same hat it and the hats other parameters would be changed too.

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
As you can see code first use `newHatId = getNextId(_admin);` to get the new hat id and then call `_checkAdmin()` which makes external calls and in the last line code increase the value of the `_hats[_admin].lastHatId`. this would give attacker opportunity to perform reentrancy attack by doing this:
1. a malicious User1 who is admin of the Hat1 wants to create Hat2(under Hat1) with maxSupply equal to 1 but mint the Hat2 for 3 people.
2. User1 would set toggle address value for Hat1 to his malicious contract(MaliciousToggle1) to be ready for reentrancy. and also it would give MaliciousToggle1 admin access to Hat1 by wearing upper level hats of Hat1 for MaliciousToggle1.
3. User1 would call `createHat()` to create Hat2 under Hat1. the maxSupply is 1. code would calculate `newHatId` for Hat1 base on the `_hats[Hat1].lastHatId`. let's assume the id is ID1.
4. then code would call `_checkAdmin(newHatId)` and this function would check to see that the caller (User1) is admin of the upper level hats or not and in doing so it would call MaliciousToggle1 contract(to check Hat1 active status)
5. now User1's MaliciousToggle1 would call `createHat()` and set admin as Hat1 and maxSupply as 3 (User1 added MaliciousToggle1 to Hat1 admins too in upper levels and also MalicisouToggle1 won't perform reentrancy this time when get called during admin checking). code would create Hat2 with ID1 and maxSupply as 3.
6. now MaliciousToggle1 would call `mintHat(ID1, )` for 3 address and code would increase balance of those 3 address in Hat2.
7. now MaliciousToggle1 would return (reentrancy would be done) and in the rest of the `createHat()` code would set the maxSupply of the ID1 as 1.
8. in the end Hat2 has maxSupply as 1 but 3 user wear Hat2 hats. and also code emits creating Hat2 for two times with different values. there can be another attacks too by performing this reentrancy.

## Impact
malicious admins can create hats and bypass maxSupply check and mint hat for more users. This can cause serious issues if any other logics depends on the maxSupply as true value for the maximum hat wearer. also other issues like changing values of the immutable hat can be done.

## Code Snippet
https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L143-L170

## Tool used
Manual Review

## Recommendation
follow check-effect-interaction pattern. one solution can be moving `_checkAdmin()` to first line of function.