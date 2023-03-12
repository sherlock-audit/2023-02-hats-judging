obront

medium

# If signer gate is deployed to safe with more than 5 existing modules, safe will be bricked

## Summary

`HatsSignerGate` can be deployed with a fresh safe or connected to an existing safe. In the event that it is connected to an existing safe, it pulls the first 5 modules from that safe to count the number of connected modules. If there are more than 5 modules, it silently only takes the first five. This results in a mismatch between the real number of modules and `enabledModuleCount`, which causes all future transactions to revert.

## Vulnerability Detail

When a `HatsSignerGate` is deployed to an existing safe, it pulls the existing modules with the following code:
```solidity
(address[] memory modules,) = GnosisSafe(payable(_safe)).getModulesPaginated(SENTINEL_MODULES, 5);
uint256 existingModuleCount = modules.length;
```
Because the modules are requested paginated with `5` as the second argument, it will return a maximum of 5 modules. If the safe already has more than 5 modules, only the first 5 will be returned. 

The result is that, while the safe has more than 5 modules, the gate will be set up with `enabledModuleCount = 5 + 1`. 

When a transaction is executed, `checkTransaction()` will get the hash of the first 6 modules:
```solidity
(address[] memory modules,) = safe.getModulesPaginated(SENTINEL_OWNERS, enabledModuleCount);
_existingModulesHash = keccak256(abi.encode(modules));
```

After the transaction, the first 7 modules will be checked to compare it:
```solidity
(address[] memory modules,) = safe.getModulesPaginated(SENTINEL_OWNERS, enabledModuleCount + 1);
if (keccak256(abi.encode(modules)) != _existingModulesHash) {
    revert SignersCannotChangeModules();
}
```

Since it already had more than 5 modules (now 6, with HatsSignerGate added), there will be a 7th module and the two hashes will be different. This will cause a revert.

This would be a high severity issue, except that in the comments for the function it says:

> /// @dev Do not attach HatsSignerGate to a Safe with more than 5 existing modules; its signers will not be able to execute any transactions

This is the correct recommendation, but given the substantial consequences of getting it wrong, it should be enforced in code so that a safe with more modules reverts, rather than merely suggested in the comments.

## Impact

If a HatsSignerGate is deployed and connected to a safe with more than 5 existing modules, all future transactions sent through that safe will revert.

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateFactory.sol#L124-L141

## Tool used

Manual Review

## Recommendation

The `deployHatsSignerGate()` function should revert if attached to a safe with more than 5 modules:
```diff
function deployHatsSignerGate(
    uint256 _ownerHatId,
    uint256 _signersHatId,
    address _safe, // existing Gnosis Safe that the signers will join
    uint256 _minThreshold,
    uint256 _targetThreshold,
    uint256 _maxSigners
) public returns (address hsg) {
    // count up the existing modules on the safe
    (address[] memory modules,) = GnosisSafe(payable(_safe)).getModulesPaginated(SENTINEL_MODULES, 5);
    uint256 existingModuleCount = modules.length;
+   (address[] memory modulesWithSix,) = GnosisSafe(payable(_safe)).getModulesPaginated(SENTINEL_MODULES, 6);
+   if (modules.length != moduleWithSix.length) revert TooManyModules();

    return _deployHatsSignerGate(
        _ownerHatId, _signersHatId, _safe, _minThreshold, _targetThreshold, _maxSigners, existingModuleCount
    );
}
```