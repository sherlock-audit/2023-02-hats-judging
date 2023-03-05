ktg

medium

# Inactive hats can still be minted and transferred

## Summary
Currently there's no check if a hat is active in function `mintHat` and `transferHat`, this can lead to abuse concerns.
A user could be unaware that he/she is wearing a hat (and having a responsibility associated with it) because function `isWearerOfHat` will always return `false` and there is no external/public function to view their `static balance` of a hat.


## Vulnerability Detail
Function `mintHat` is implemented as follow:
```solidity
function mintHat(uint256 _hatId, address _wearer) public returns (bool success) {
        Hat storage hat = _hats[_hatId];
        if (hat.maxSupply == 0) revert HatDoesNotExist(_hatId);

        if (!isEligible(_wearer, _hatId)) revert NotEligible();

        // only the wearer of a hat's admin Hat can mint it
        _checkAdmin(_hatId);

        if (hat.supply >= hat.maxSupply) {
            revert AllHatsWorn(_hatId);
        }

        if (_staticBalanceOf(_wearer, _hatId) > 0) {
            revert AlreadyWearingHat(_wearer, _hatId);
        }

        _mintHat(_wearer, _hatId);

        success = true;
    }
```
There is no check if a hat is active or not.
The current `isWearerOfHat` function:
```solidity
function isWearerOfHat(address _user, uint256 _hatId) public view returns (bool isWearer) {
        isWearer = (balanceOf(_user, _hatId) > 0);
    }
function balanceOf(address _wearer, uint256 _hatId)
        public
        view
        override(ERC1155, IHats)
        returns (uint256 balance)
    {
        Hat storage hat = _hats[_hatId];

        balance = 0;

        if (_isActive(hat, _hatId) && _isEligible(_wearer, hat, _hatId)) {
            balance = super.balanceOf(_wearer, _hatId);
        }
    }
```
This will always return `false` if the hat is not active. The problem is that this codes does not differentiate between 2 cases: (hat is inactive + user balance =0) and (hat is inactive + user balance = 1). So there's no way a normal user to know if they are in minted a hat.

Here is a POC
```solidity
contract InActiveHatTest is TestSetup {

    function testInActiveHat() public {

        // Change maxSupply  = 2 for minting new hat wearer
        _maxSupply = 2;
        (uint256[] memory ids, address[] memory wearers) = createHatsBranch(3, topHatId, topHatWearer, false);
        assertEq(hats.getHatLevel(ids[2]), 3);
        assertEq(hats.getAdminAtLevel(ids[0], 0), topHatId);
        assertEq(hats.getAdminAtLevel(ids[1], 1), ids[0]);
        assertEq(hats.getAdminAtLevel(ids[2], 2), ids[1]);

        (,uint32 maxSupply2,,,,,,,) = hats.viewHat(ids[2]);
        assertEq(maxSupply2, 2);

        // now make hat ids[2] inactive?
        vm.prank(_toggle);
        hats.setHatStatus(ids[2], false);
        (,,uint32 supply2,,,,,,bool active2) = hats.viewHat(ids[2]);
        assertEq(active2, false);
        assertEq(supply2, 1);

        address newWearer = address(0x0ABCD);
        vm.prank(wearers[1]);
        hats.mintHat(ids[2], newWearer);
        (,,supply2,,,,,,) = hats.viewHat(ids[2]);
        assertEq(supply2, 2);

        assertEq(hats.isWearerOfHat(newWearer, ids[2]), false);

    }

}
```
Command to run this test `forge test --match-path test/Hats.t.sol -vvvv --match-contract InActiveHatTest`. 

## Impact
- Inactive hat could be minted and transferred
- Users not aware if they are wearing an inactive hat

## Code Snippet
https://github.com/Hats-Protocol/hats-protocol/blob/fafcfdf046c0369c1f9e077eacd94a328f9d7af0/src/Hats.sol#L241-#L261
## Tool used

Manual Review

## Recommendation
I recommend only allow minting/transferring of active hats.
