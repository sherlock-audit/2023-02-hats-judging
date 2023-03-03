obront

high

# If a hat is owned by address(0), phony signatures will be accepted by the safe

## Summary

If a hat is sent to `address(0)`, the multisig will be fooled into accepting phony signatures on its behalf. This will throw off the proper accounting of signatures, allowing non-majority transactions to pass and potentially allowing users to steal funds.

## Vulnerability Detail

In order to validate that all signers of a transaction are valid signers, `HatsSignerGateBase.sol` implements the `countValidSignatures()` function, which recovers the signer for each signature and checks `isValidSigner()` on them.

The function uses `ecrecover` to get the signer. However, `ecrecover` is well known to return `address(0)` in the event that a phony signature is passed with a `v` value other than 27 or 28. See [this example](https://gist.github.com/axic/5b33912c6f61ae6fd96d6c4a47afde6d) for how this can be done.

In the event that this is a base with only a single hat approved for signing, the `isValidSigner()` function will simply check if the owner is the wearer of a hat:
```solidity
function isValidSigner(address _account) public view override returns (bool valid) {
    valid = HATS.isWearerOfHat(_account, signersHatId);
}
```
On the `Hats.sol` contract, this simply checks their balance:
```solidity
function isWearerOfHat(address _user, uint256 _hatId) public view returns (bool isWearer) {
    isWearer = (balanceOf(_user, _hatId) > 0);
}
```
... which only checks if it is active or eligible...
```solidity
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
... which calls out to ERC1155, which just returns the value in storage (without any address(0) check)...
```solidity
function balanceOf(address owner, uint256 id) public view virtual returns (uint256 balance) {
    balance = _balanceOf[owner][id];
}
```

The result is that, if a hat ends up owned by `address(0)` for any reason, this will give blanket permission for anyone to create a phony signature that will be accepted by the safe.

You could imagine a variety of situations where this may apply:
- An admin minting a mutable hat to address(0) to adjust the supply while waiting for a delegatee to send over their address to transfer the hat to
- An admin sending a hat to address(0) because there is some reason why they need the supply slightly inflated
- An admin accidentally sending a hat to address(0) to burn it

None of these examples are extremely likely, but there would be no reason for the admin to think they were putting their multisig at risk for doing so. However, the result would be a free signer on the multisig, which would have dramatic consequences.

## Impact

If a hat is sent to `address(0)`, any phony signature can be accepted by the safe, leading to transactions without sufficient support being executed. 

This is particularly dangerous in a 2/3 situation, where this issue would be sufficient for a single party to perform arbitrary transactions.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L547-L591

## Tool used

Manual Review

## Recommendation

The easiest option is to add a check in `countValidSignatures()` that confirms that `currentOwner != address(0)` after each iteration.

For extra security, you may consider implementing a check in `balanceOf()` that errors if we use `address(0)` as the address to check. (This is what OpenZeppelin does in their ERC721 implementation: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7f028d69593342673492b0a0b1679e2a898cf1cf/contracts/token/ERC721/ERC721.sol#L62-L65)