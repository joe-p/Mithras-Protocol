import { describe, expect, it } from "vitest";
import {
  DiscoveryKeypair,
  SpendSeed,
  TweakedSigner,
  deriveTweakedPubkey,
  deriveTweakScalar,
} from "../src/keypairs";
import {
  computeDiscoverySecretSender,
  computeDiscoverySecretReceiver,
  computeDiscoveryTag,
} from "../src/discovery";
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
    const spend = SpendSeed.generate();
    const discovery = DiscoveryKeypair.generate();

    expect(spend.seed).toHaveLength(32);
    expect(discovery.publicKey).toHaveLength(32);
  });

  it("discovery secret computation", () => {
    const discovery = DiscoveryKeypair.generate();
    const ephemeral = DiscoveryKeypair.generate();

    const secretSender = computeDiscoverySecretSender(
      ephemeral.privateKey,
      discovery.publicKey,
    );
    const secretReceiver = computeDiscoverySecretReceiver(
      discovery.privateKey,
      ephemeral.publicKey,
    );

    expect(secretSender).toEqual(secretReceiver);
  });

  it("tweaked keypair computation", () => {
    const spend = SpendSeed.generate();
    const discovery = DiscoveryKeypair.generate();
    const ephemeral = DiscoveryKeypair.generate();

    const discoverySecret = computeDiscoverySecretSender(
      ephemeral.privateKey,
      discovery.publicKey,
    );
    const tweakScalar = deriveTweakScalar(discoverySecret);

    const tweakedPubSender = deriveTweakedPubkey(spend.publicKey, tweakScalar);

    // TweakedSigner.derive is an instance method; create a dummy to call it
    const tweakedReceiver = TweakedSigner.derive(spend, tweakScalar);

    expect(tweakedPubSender).toEqual(tweakedReceiver.publicKey);
  });

  it("discovery tag", () => {
    const discovery = DiscoveryKeypair.generate();
    const ephemeral = DiscoveryKeypair.generate();

    const secretSender = computeDiscoverySecretSender(
      ephemeral.privateKey,
      discovery.publicKey,
    );
    const secretReceiver = computeDiscoverySecretReceiver(
      discovery.privateKey,
      ephemeral.publicKey,
    );

    const sender = new Uint8Array(32);
    const lease = new Uint8Array(32);

    const tagSender = computeDiscoveryTag(
      secretSender,
      sender,
      1000n,
      2000n,
      lease,
    );
    const tagReceiver = computeDiscoveryTag(
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
    const recipient = DiscoveryKeypair.generate();

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
    const spend = SpendSeed.generate();
    const discovery = DiscoveryKeypair.generate();
    const tweakScalar = deriveTweakScalar(new Uint8Array(32).fill(42));

    const tweakedReceiver = TweakedSigner.derive(spend, tweakScalar);

    const addr = MithrasAddr.fromKeys(
      tweakedReceiver.publicKey,
      discovery.publicKey,
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
    expect(decoded.discX25519).toEqual(addr.discX25519);
  });

  it("complete mithras protocol flow with utxo generate", async () => {
    const spend = SpendSeed.generate();
    const discovery = DiscoveryKeypair.generate();

    const addr = MithrasAddr.fromKeys(
      spend.publicKey,
      discovery.publicKey,
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
      discovery,
      txnMetadata,
    );

    expect(recoveredSecrets.spendingSecret).toEqual(
      utxoInputs.secrets.spendingSecret,
    );
    expect(recoveredSecrets.nullifierSecret).toEqual(
      utxoInputs.secrets.nullifierSecret,
    );
    expect(recoveredSecrets.amount).toBe(utxoInputs.secrets.amount);
    expect(recoveredSecrets.tweakScalar).toBe(utxoInputs.secrets.tweakScalar);
    expect(recoveredSecrets.tweakedPubkey).toEqual(
      utxoInputs.secrets.tweakedPubkey,
    );
  });

  it("mimc matches avm", () => {
    const expected =
      49105172669127360405434456472687549054927962593265498033454743191558675115881n;

    const input = [13n, 37n];

    expect(mimcSum(input)).toBe(expected);
  });
});
