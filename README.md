# Mithras Protocol

The Mithras Protocol is a privacy-focused UTXO protocol built on top of Algorand via smart contracts and zero-knowledge proofs. The primary use case in mind is cash-based assistance which requires the following properties:

- Initial deposits should be auditable (i.e an NGO can prove they dispersed funds)
- Usage of funds after deposit should be private
- Support for ASAs

This protocol, however, could also be used for any other use case that requires private transactions on Algorand.

## Status

Mithras is currently in development and none of it has been audited. It is not production-ready.

A full end-to-end flow of depositing, spending, and tracking balance is available in [this e2e test](./packages/mithras-subscriber/__test__/e2e.test.ts).

## Protocol

### Components

Each user of the Mithras protocol has one or more addresses. The address is a bech32 string that looks something like the following:

`mith1qyqsq4unvdxs3mueg3upw2pe97qccdknyz0xs3ztpufy8dchd99ve9kf625z8he8xsea2pjrwrud4mgncu7rcldxyw7qvuw5jmkj9t9jsu4qy08t0n`

The address is derived from two key pairs: a view key pair and a spend key pair. The view key pair is used to view transactions on the blockchain. The spend key pair is used to actually spend the funds. This separation of keys allows someone to share their transaction history and balance with other parties without putting their funds at risk.

It is also possible for a user to have multiple addresses with various view keys. This allows for selective disclosure of transaction history and balance.

To spend funds, the user must generate a ZK proof that they have the right to spend the funds. This proof is then validated by a smart contract which also inserts the UTXO into a Merkle tree. Spending authorization is enforced by the Algorand protocol via the ed25519 signature on the transaction that interacts with the smart contract.

### Cost

Due to the ZK verification and Merkle tree management, spending a UTXO on Mithras is more expensive than a regular Algorand transaction. The cost of spending a single UTXO is 0.071 ALGO. It should be noted that transactions may involve multiple UTXO spends which would increase the cost.

### Speed

On a M4 Pro the wasm-based ZK proof generation takes roughly 8 seconds for a UTXO spend. In many cases more than one UTXO will need to be spent at a time. Proof generation can, however, be done in parallel (note: not yet tested) so the time it takes to generate proofs for multiple UTXOs is not necessarily linear.

### Infrastructure

Interacting with the Mithras protocol requires access to full transaction history of the Algorand blockchain starting from the round the mithras app was created. This is required because transaction history is needed to reconstruct the full Merkle tree of UTXOs. This means when a client-side application wants to get balance and available UTXOs for a given address, the full chain history must be processed to do so. Abstractions over the AlgoKit subscriber are provided to make this process as easy as possible with just a regular archival node. This, however, can also be done with a dedicated server that is constantly watching the chain. This server does not need access to the spending key and just needs the view key. This means if the server is compromised privacy is lost but funds are not at risk.

### Example: Aid Distribution Flow

A Mithras account has two components: a view key pair and a spend key pair. The view key pair is used to view transactions on the blockchain. The spend key pair is used to actually spend the funds. This enables the following flow for aid distribution:

1. An NGO creates a view key pair and shares the key pair with the recipient and any auditors
1. The recipient creates a spend key pair and shares the public key with the NGO
1. The NGO sends funds to the recipient using the view key from step 1 and the spend public key from step 2
   - Any outside observer without the view key cannot see the recipient or the amount being sent
   - The NGO, auditors, and recipient can see the amount being sent and prove it was sent to the intended recipient
1. The recipient can now spend the funds privately using the spend key pair.
   - NGO and auditors can no longer track the funds
1. The recipient can generate a new view key pair (but keep their spend key pair) and use it to privately receive funds (i.e. P2P payments)

### Technical Details

For details about the protocol, please refer to [PROTOCOL.md](PROTOCOL.md).

### Future Work

- Support withdrawals
- Support for ASAs
- Switch from MiMC to Poseidon2 for more efficient hashing in circuit and on-chain (blocked by this [PR](https://github.com/algorand/go-algorand/pull/6560))
  - This should result in slightly faster proving times
  - This should also enable cheaper on-chain fees
- Look into using zkVMs as a way to aggregate multiple UTXO spends into a single proof.
  - The main benefit here would be lower on-chain fees with atomicity
  - The main downside is that most zkVMs still use bn254 for on-chain proofs which has weaker security than BLS12-381
- Create docker compose for running a subscriber in a TEE (i.e. on Phala or Nillion)
