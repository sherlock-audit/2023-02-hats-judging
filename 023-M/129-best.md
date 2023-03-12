w42d3n

medium

# HatsSignerGateBase.countValidSignatures() is susceptible to replay attacks

## Summary

Use of ecrecover is susceptible to signature malleability which could lead to replay attacks


## Vulnerability Detail

The function countValidSignatures() use the function ecrecover to verify data signatures.

The built-in EVM precompile ecrecover is susceptible to signature malleability (because of non-unique s and v values)  which could lead to replay attacks. 

## Impact

The function countValidSignatures() is susceptible to replay attacks.

Therefore the number of hats-valid signatures within a set of `signatures` might be wrong which is used to 'check transactions'.

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L488

```
 uint256 validSigCount = countValidSignatures(txHash, signatures, signatures.length / 65);
```

## Code Snippet

https://github.com/Hats-Protocol/hats-zodiac/blob/9455cc0957762f5dbbd8e62063d970199109b977/src/HatsSignerGateBase.sol#L570-578

```
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner =
                    ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, v, r, s);
            }
```          


## Tool used

Manual Review

## Recommendation

Consider using OpenZeppelin’s ECDSA library (which prevents this malleability) instead of the built-in function: 

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/cryptography/ECDSA.sol

## References

https://swcregistry.io/docs/SWC-117 

https://swcregistry.io/docs/SWC-121  

https://medium.com/cryptronics/signature-replay-vulnerabilities-in-smart-contracts-3b6f7596df57)

https://medium.com/multichainorg/anyswap-multichain-router-v3-exploit-statement-6833f1b7e6fb

