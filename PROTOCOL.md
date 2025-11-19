# Mithras

## Keypairs

### Spend Keypair

- **Type:** Ed25519 keypair
- **Purpose:** Long-term spend authority.
  - Public part $P = s·G$ can be shared so senders can derive one-time spend keys.
  - Private part $s$ is the clamped Ed25519 secret scalar derived from the 32-byte seed (not the raw seed itself). The seed also derives a `prefix` used for deterministic nonces when signing. Neither appear on-chain.

### Tweaked One-Time Spend Keypair

- **Type:** Ed25519 keypair
- **Purpose:** Unique per UTXO; used for locking and spending that output.
  - Public: $P' = P + t·G$ (computed by sender)
  - Private: $s' = (s + t) \\bmod q$ (computed by receiver); reuse the base key's `prefix` for signing.
- **Privacy:** Unlinkable to $P$ without knowing $t$.
- **Sender:** Can compute $P'$ but not $s'$.
- **Receiver:** Can compute $s'$ (and thus $P'$) from $s$ and $t$.

### Stealth Address *(Friendly Term)*

- **Meaning:** Wallet-friendly label for the public part of a Tweaked One-Time Spend Keypair.
- **Notes:** One stealh address = one UTXO; not reused.

### Discovery Keypair

- **Type:** X25519 keypair
- **Purpose:** Enables scanning to detect relevant outputs.
  - Public: $D = d·G$ — given to senders to allow them to derive the shared secret.
  - Private: $d$ — used with sender’s ephemeral pubkey $R$ to derive the shared secret.
- **Security:** Can be given to watch-only wallets without risking spending.

## Secrets

### Discovery Secret

- **Type:** 32-byte shared secret from ECDH:
  - Sender: $T = r·D$
  - Receiver: $T = d·R$
- **Purpose:** Input for:
  - Tweak scalar $t$ for spend key derivation.
  - Key for computing the discovery tag.

### Discovery Tag

- **Formula:**

  ```text
  tag_key = HKDF-Expand(HKDF-Extract(0, discovery_secret),
                        "discovery-tag", 32)
  tag = HMAC(tag_key || sender || fv || lv || lease)
  ```

- **Purpose:** Small value in tx header that lets receiver quickly identify their outputs.

- **Privacy:** Outsiders can’t link tags without `discovery_secret`.

### Spend Secret

- **Type:** 64-byte secret encrypted via HPKE.
- **Purpose:** Contains the `spending_secret` and `nullifier_secret` used as private inputs to the ZK circuit for spending the UTXO.
- **Security:** Cannot be used to spend the UTXO without the corresponding one-time spend private key `s'`; signature verification is enforced by the smart contract.
- **Privacy:** Leakage can enable transaction graph and nullifier linkability, and may allow pre-computation of nullifiers for future spends.

## Who Knows What Table

| Value                           | Sender | Receiver | Observer (Blockchain) |
| ------------------------------- | ------ | -------- | --------------------- |
| **Spend privkey** `s`           | No     | Yes      | No                    |
| **Spend pubkey** `P`            | Yes    | Yes      | Possibly (published)  |
| **Discovery privkey** `d`       | No     | Yes      | No                    |
| **Discovery pubkey** `D`        | Yes    | Yes      | Possibly (published)  |
| **Ephemeral privkey** `r`       | Yes    | No       | No                    |
| **Ephemeral pubkey** `R`        | Yes    | Yes      | Yes (in tx)           |
| **Discovery secret** `T`        | Yes    | Yes      | No                    |
| **Tweak scalar** `t`            | Yes    | Yes      | No                    |
| **One-time spend privkey** `s'` | No     | Yes      | No                    |
| **One-time spend pubkey** `P'`  | Yes    | Yes      | Yes (locks UTXO)      |
| **Discovery tag** `tag`         | Yes    | Yes      | Yes (in tx)           |
| **Spend secret**                | Yes    | Yes      | No (encrypted in tx)  |

## Circuits

### Deposit Circuit

#### Public Input Signals

- `amount`: The amount being deposited into the protocol
- `receiver`: The public key of the tweaked one-time spend keypair that can spend the deposited amount

#### Private Input Signals

- `spending_secret`: Secret needed to spend the deposited amount
- `nullifier_secret`: Second secret needed to spend the deposited amount. Used in nullifier generation

#### Public Output Signals

- `commitment`: `Hash(spending_secret || nullifier_secret || amount || receiver)`

### Spend Circuit

#### Public Input Signals

- `fee`: The fee (in uALGO) paid for the transaction
- `utxo_spender`: The public key of the tweaked one-time spend keypair that can spend the UTXO (i.e the `receiver`). Signature check done by smart contract.

#### Private Input Signals

- `utxo_spending_secret`: Secret needed to spend the UTXO

- `utxo_nullifier_secret`: Second secret needed to spend the UTXO. Used in nullifier generation

- `utxo_amount`: The amount available in the UTXO

- `path_selectors`: Booleans indicating left/right child at each level of the Merkle path

- `utxo_path`: The Merkle path to the UTXO in the tree with root `utxo_root`

- `out0_amount`: The first output amount that is spent in the transaction

- `out0_receiver`: The public key of the tweaked one-time spend keypair that can spend `out0_amount`

- `out0_spending_secret`: Secret needed to spend `out0_amount`

- `out0_nullifier_secret`: Second secret needed to spend `out0_amount`. Used in nullifier generation

- `out1_amount`: The second output amount that is spent in the transaction

- `out1_receiver`: The public key of the tweaked one-time spend keypair that can spend `out1_amount`

- `out1_spending_secret`: Secret needed to spend `out1_amount`

- `out1_nullifier_secret`: Second secret needed to spend `out1_amount`. Used in nullifier generation

#### Public Output Signals

- `out0_commitment`: `Hash(out0_spending_secret || out0_nullifier_secret || out0_amount || out0_receiver)`
- `out1_commitment`: `Hash(out1_spending_secret || out1_nullifier_secret || out1_amount || out1_receiver)`
- `utxo_root`: The root of the Merkle tree that contains the UTXO
- `utxo_nullifier`: `Hash(utxo_commitment || utxo_nullifier_secret)`

### Constraints

- `out0_amount + out1_amount + fee = utxo_amount`
