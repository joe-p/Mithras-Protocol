import { describe, expect, it } from "vitest";
import {
  ViewKeypair,
  SpendKeypair,
  StealthKeypair,
  deriveStealthPubkey,
  deriveStealthScalar,
} from "../src/keypairs";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  computeViewSecretSender,
  computeViewSecretReceiver,
  computeViewTag,
} from "../src/view";
import {
  HpkeEnvelope,
  SupportedHpkeSuite,
  SupportedNetworks,
  TransactionMetadata,
  getHpkeSuite,
} from "../src/hpke";
import { MithrasAddr } from "../src/address";
import { UtxoInputs, UtxoSecrets } from "../src/utxo";
import { mimcSum } from "../src/mimc";

describe("mithras protocol", () => {
  it("keypair generation", () => {
    const spend = SpendKeypair.generate();
    const view = ViewKeypair.generate();

    expect(spend.seed).toHaveLength(32);
    expect(view.publicKey).toHaveLength(32);
  });

  it("view secret computation", () => {
    const view = ViewKeypair.generate();
    const ephemeral = ViewKeypair.generate();

    const secretSender = computeViewSecretSender(
      ephemeral.privateKey,
      view.publicKey,
    );
    const secretReceiver = computeViewSecretReceiver(
      view.privateKey,
      ephemeral.publicKey,
    );

    expect(secretSender).toEqual(secretReceiver);
  });

  it("stealth keypair computation", () => {
    const spend = SpendKeypair.generate();
    const view = ViewKeypair.generate();
    const ephemeral = ViewKeypair.generate();

    const viewSecret = computeViewSecretSender(
      ephemeral.privateKey,
      view.publicKey,
    );
    const stealthScalar = deriveStealthScalar(viewSecret);

    const stealthPubSender = deriveStealthPubkey(
      spend.publicKey,
      stealthScalar,
    );

    // StealthKeypair.derive is an instance method; create a dummy to call it
    const stealthReceiver = StealthKeypair.derive(spend, stealthScalar);

    expect(stealthPubSender).toEqual(stealthReceiver.publicKey);
  });

  it("view tag", () => {
    const view = ViewKeypair.generate();
    const ephemeral = ViewKeypair.generate();

    const secretSender = computeViewSecretSender(
      ephemeral.privateKey,
      view.publicKey,
    );
    const secretReceiver = computeViewSecretReceiver(
      view.privateKey,
      ephemeral.publicKey,
    );

    const sender = new Uint8Array(32);
    const lease = new Uint8Array(32);

    const tagSender = computeViewTag(secretSender, sender, 1000n, 2000n, lease);
    const tagReceiver = computeViewTag(
      secretReceiver,
      sender,
      1000n,
      2000n,
      lease,
    );

    expect(tagSender).toEqual(tagReceiver);
  });

  it("hpke encryption decryption", async () => {
    const hpke = getHpkeSuite(SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305);
    const recipient = ViewKeypair.generate();

    const info = new TextEncoder().encode("mithras|network:0|app:1337|v:1");
    const aad = new TextEncoder().encode("txid:BLAH...BLAH");

    const recipientPub = await hpke.kem.deserializePublicKey(
      recipient.publicKey,
    );
    const senderCtx = await hpke.createSenderContext({
      recipientPublicKey: recipientPub,
      info,
    });

    const mithrasSecret = new UtxoSecrets(
      new Uint8Array(32).fill(42),
      new Uint8Array(32).fill(43),
      1000n,
      7n,
      new Uint8Array(32),
    );
    const secretBytes = mithrasSecret.toBytes();
    const ct = new Uint8Array(await senderCtx.seal(secretBytes, aad));
    const enc = new Uint8Array(senderCtx.enc);

    // Serialize and deserialize through HpkeEnvelope
    const env = new HpkeEnvelope(
      1,
      SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
      enc,
      ct,
      new Uint8Array(32),
      enc.slice(),
    );

    const envBytes = env.toBytes();
    const env2 = HpkeEnvelope.fromBytes(envBytes);

    const recipientKey = await hpke.kem.deserializePrivateKey(
      recipient.privateKey,
    );
    const recvCtx = await hpke.createRecipientContext({
      recipientKey,
      enc: env2.encapsulatedKey,
      info,
    });

    const pt = new Uint8Array(await recvCtx.open(env2.ciphertext, aad));
    expect(pt).toEqual(secretBytes);
  });

  it("mithras address encoding decoding", () => {
    const spend = SpendKeypair.generate();
    const view = ViewKeypair.generate();
    const stealthScalar = deriveStealthScalar(new Uint8Array(32).fill(42));

    const stealthReceiver = StealthKeypair.derive(spend, stealthScalar);

    const addr = MithrasAddr.fromKeys(
      stealthReceiver.publicKey,
      view.publicKey,
      1,
      SupportedNetworks.Testnet,
      SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
    );

    const encoded = addr.encode();
    const decoded = MithrasAddr.decode(encoded);

    expect(decoded.version).toBe(addr.version);
    expect(decoded.network).toBe(addr.network);
    expect(decoded.suite).toBe(addr.suite);
    expect(decoded.spendEd25519).toEqual(addr.spendEd25519);
    expect(decoded.viewX25519).toEqual(addr.viewX25519);
  });

  it("complete mithras protocol flow with utxo generate", async () => {
    const spend = SpendKeypair.generate();
    const view = ViewKeypair.generate();

    const addr = MithrasAddr.fromKeys(
      spend.publicKey,
      view.publicKey,
      1,
      SupportedNetworks.Testnet,
      SupportedHpkeSuite.x25519Sha256ChaCha20Poly1305,
    );

    const txnMetadata = new TransactionMetadata(
      new Uint8Array(32),
      1000n,
      2000n,
      new Uint8Array(32),
      SupportedNetworks.Mainnet,
      1337n,
    );

    const utxoInputs = await UtxoInputs.generate(txnMetadata, 1000n, addr);

    const recoveredSecrets = await UtxoSecrets.fromHpkeEnvelope(
      utxoInputs.hpkeEnvelope,
      view,
      txnMetadata,
    );

    expect(recoveredSecrets.spendingSecret).toEqual(
      utxoInputs.secrets.spendingSecret,
    );
    expect(recoveredSecrets.nullifierSecret).toEqual(
      utxoInputs.secrets.nullifierSecret,
    );
    expect(recoveredSecrets.amount).toBe(utxoInputs.secrets.amount);
    expect(recoveredSecrets.stealthScalar).toBe(
      utxoInputs.secrets.stealthScalar,
    );
    expect(recoveredSecrets.stealthPubkey).toEqual(
      utxoInputs.secrets.stealthPubkey,
    );
  });

  it("stealth signer signing and verification", () => {
    const spend = SpendKeypair.generate();
    const view = ViewKeypair.generate();
    const ephemeral = ViewKeypair.generate();

    const viewSecret = computeViewSecretSender(
      ephemeral.privateKey,
      view.publicKey,
    );
    const stealthScalar = deriveStealthScalar(viewSecret);

    const stealthSigner = StealthKeypair.derive(spend, stealthScalar);

    const message = new TextEncoder().encode("hello mithras");
    const signature = stealthSigner.rawSign(message);

    expect(signature).toHaveLength(64);

    // Verify the signature using ed25519.verify against the stealth public key
    const isValid = ed25519.verify(signature, message, stealthSigner.publicKey);
    expect(isValid).toBe(true);

    // Verify that a different message fails verification
    const wrongMessage = new TextEncoder().encode("wrong message");
    const isInvalid = ed25519.verify(
      signature,
      wrongMessage,
      stealthSigner.publicKey,
    );
    expect(isInvalid).toBe(false);

    const derivedPubkey = deriveStealthPubkey(spend.publicKey, stealthScalar);

    expect(derivedPubkey).toEqual(stealthSigner.publicKey);
  });

  it("mimc matches avm", () => {
    const expected =
      49105172669127360405434456472687549054927962593265498033454743191558675115881n;

    const input = [13n, 37n];

    expect(mimcSum(input)).toBe(expected);
  });
});
