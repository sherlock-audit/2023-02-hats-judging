rvierdiiev

medium

# HatsSignerGate.claimSigner will revert when signerCount = maxSigners and any of owners is invalid

## Summary
HatsSignerGate.claimSigner will revert when signerCount = maxSigners and any of owners is invalid. As result new signer will not be able to become owner.
## Vulnerability Detail
HatsSignerGate.claimSigner is called by hat wearer in order to become Safe owner.
https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGate.sol#L36-L69
```solidity
    function claimSigner() public virtual {
        uint256 maxSigs = maxSigners; // save SLOADs
        uint256 currentSignerCount = signerCount;


        if (currentSignerCount >= maxSigs) {
            revert MaxSignersReached();
        }


        if (safe.isOwner(msg.sender)) {
            revert SignerAlreadyClaimed(msg.sender);
        }


        if (!isValidSigner(msg.sender)) {
            revert NotSignerHatWearer(msg.sender);
        }


        /* 
        We check the safe owner count in case there are existing owners who are no longer valid signers. 
        If we're already at maxSigners, we'll replace one of the invalid owners by swapping the signer.
        Otherwise, we'll simply add the new signer.
        */
        address[] memory owners = safe.getOwners();
        uint256 ownerCount = owners.length;


        if (ownerCount >= maxSigs) {
            bool swapped = _swapSigner(owners, ownerCount, maxSigs, currentSignerCount, msg.sender);
            if (!swapped) {
                // if there are no invalid owners, we can't add a new signer, so we revert
                revert NoInvalidSignersToReplace();
            }
        } else {
            _grantSigner(owners, currentSignerCount, msg.sender);
        }
    }
```

The first check in function checks that `signerCount`(count of valid owners that were updated last time) are less than `maxSigners`(maximum allowed signers count. Otherwise function will revert.

But it's possible, that between last update of `signerCount` variable, some owner already became invalid and he should be changed by claimer, but function will revert.
Claimer will need to call `reconcileSignerCount` function in order to update `signerCount` function and be able to call `claimSigner` function.
## Impact
Claimer can't become a signer as `signerCount` isn't updated.
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
I guess, that you don't need that check. Or the check can be `currentSignerCount > maxSigs`(without = sign). In case if each owner is valid, function will not swap any owner to claimer.
And in case if any owner became invalid, then function will swap it.