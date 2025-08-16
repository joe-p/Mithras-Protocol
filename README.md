# Mithras Protocol

The Mithras Protocol is a privacy-focused UTXO protocol built on top of Algorand via smart contracts and zero-knowledge proofs. The primary use case in mind is cash-based assistance which requires the following properties:

- Initial deposits should be auditable (i.e an NGO can prove they dispersed funds)
- Usage of funds after deposit should be private
- Support for ASAs

This protocol, however, could also be used for any other use case that requires private transactions on Algorand.

## Status

Mithras is currently in development. The original proof-of-concept can be found [here](https://github.com/joe-p/Mithras-Protocol-POC). The proof of concept is a fork of [Hermes Vault](https://github.com/giuliop/HermesVault-smartcontracts) and uses [AlgoPlonk](https://github.com/giuliop/AlgoPlonk) for the circuits. The new implementation in this repo is being built from scratch and will use the [Algorand SnarkJS verifier](https://github.com/joe-p/snarkjs-algorand) for the ZKP circuits.

## Technical Details

For details about the protocol, please refer to [PROTOCOL.md](PROTOCOL.md).
