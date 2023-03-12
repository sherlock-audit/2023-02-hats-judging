GimelSec

medium

# `_swapSigner()` would record a wrong `signerCount` value and allow the wrong situation by default.

## Summary

`_swapSigner()` would record a wrong `signerCount` value and allow the wrong situation by default.

## Vulnerability Detail

The purposes of `_swapSigner()` are calling `swapOwner()` and updating `signerCount`. And the `_swapSigner()` function doesn't revert if `_currentSignerCount >= _maxSigners`, which means that it allows `_currentSignerCount >= _maxSigners` to happen by default.

Also, in [L343](https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L343), the `_swapSigner()` only updates `signerCount` if `_currentSignerCount < _maxSigners`. Although it allows `_currentSignerCount >= _maxSigners` but it doesn't record a correct `signerCount` value.

Because `HatsSignerGateBase` is an abstract contract, any contract could inherit it to implement `claimSigner()`.
It would fail if someone creates a new version of singer gates and misuses `_swapSigner()`. For example, if the new version of signer gates doesn't ensure `_currentSignerCount < _maxSigners` before calling `_swapSigner()`, it will add a new valid signer even if we don't expect the `signerCount` exceeds `maxSigners`. Moreover, after the unexpected swap, it will not even record the correct `signerCount` value due to the L343 condition.

## Impact

`_swapSigner()` allows `_currentSignerCount >= _maxSigners` to happen by default. It would fail if someone creates a new version of singer gates and misuses `_swapSigner()`.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L343

## Tool used

Manual Review

## Recommendation

Revert if `_currentSignerCount >= _maxSigners`, or always `++signerCount` in `_swapSigner()`;

