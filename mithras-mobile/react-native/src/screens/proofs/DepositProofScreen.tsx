import { useRef, useState } from 'react';
import {
  ActivityIndicator,
  Button,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import {
  CircomProof,
  CircomProofResult,
  generateCircomProof,
  ProofLib,
  verifyCircomProof,
} from 'mopro-ffi';

import { loadAssets } from '../../utils/loadAssets';

type Props = {
  onBack?: () => void;
};

export function DepositProofScreen({ onBack }: Props) {
  const [spendingSecret, setSpendingSecret] = useState('111');
  const [nullifierSecret, setNullifierSecret] = useState('222');
  const [amount, setAmount] = useState('333');
  const [receiver, setReceiver] = useState('444');

  const [inputs, setInputs] = useState<string[]>([]);
  const [proof, setProof] = useState<CircomProof>({
    a: { x: '', y: '', z: '' },
    b: { x: [], y: [], z: [] },
    c: { x: '', y: '', z: '' },
    protocol: '',
    curve: '',
  });
  const [isValid, setIsValid] = useState<string>('');
  const [errorText, setErrorText] = useState<string>('');
  const [isBusy, setIsBusy] = useState(false);
  const lastResultRef = useRef<CircomProofResult | null>(null);
  const lastZkeyPathRef = useRef<string | null>(null);

  async function genProof(): Promise<void> {
    setErrorText('');
    setIsValid('');
    setIsBusy(true);
    const circuitInputs = {
      spending_secret: spendingSecret,
      nullifier_secret: nullifierSecret,
      amount,
      receiver,
    };

    if (Platform.OS === 'android' || Platform.OS === 'ios') {
      const filePath = await loadAssets('deposit.zkey', { force: true });
      const zkeyPath = filePath.replace('file://', '');
      lastZkeyPathRef.current = zkeyPath;

      try {
        const res: CircomProofResult = await generateCircomProof(
          zkeyPath,
          JSON.stringify(circuitInputs),
          ProofLib.Arkworks
        );
        lastResultRef.current = res;
        setProof(res.proof);
        setInputs(res.inputs);
      } catch (error) {
        console.error('Error generating proof:', error);
        setErrorText(String((error as any)?.message ?? error));
      } finally {
        setIsBusy(false);
      }
    }
  }

  async function verifyProof(): Promise<void> {
    setErrorText('');
    setIsBusy(true);
    if (Platform.OS === 'android' || Platform.OS === 'ios') {
      const zkeyPath =
        lastZkeyPathRef.current ??
        (await loadAssets('deposit_test.zkey', { force: true })).replace('file://', '');
      lastZkeyPathRef.current = zkeyPath;

      try {
        const circomProofResult: CircomProofResult =
          lastResultRef.current ?? {
            proof: proof,
            inputs: inputs,
          };

        if (!circomProofResult.inputs?.length) {
          setErrorText('Generate a proof first.');
          return;
        }

        const res: boolean = await verifyCircomProof(
          zkeyPath,
          circomProofResult,
          ProofLib.Arkworks
        );
        setIsValid(res.toString());
      } catch (error) {
        console.error('Error verifying proof:', error);
        setErrorText(String((error as any)?.message ?? error));
      } finally {
        setIsBusy(false);
      }
    }
  }

  return (
    <View style={styles.root}>
      {isBusy ? (
        <View style={styles.loadingOverlay} pointerEvents="auto">
          <ActivityIndicator size="large" color={stylesVars.violet} />
          <Text style={styles.loadingOverlayText}>Working…</Text>
        </View>
      ) : null}

      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.proofContainer}
        keyboardShouldPersistTaps="handled"
        testID="deposit-proof-container"
      >
        {onBack ? (
          <View style={styles.header}>
            <Pressable accessibilityRole="button" onPress={onBack} hitSlop={10}>
              <Text style={styles.backText}>Back</Text>
            </Pressable>
            <Text style={styles.headerTitle}>Deposit</Text>
            <View style={styles.headerRightSpacer} />
          </View>
        ) : null}

        <View style={styles.inputContainer}>
          <Text style={styles.label}>spending_secret</Text>
          <TextInput
            testID="deposit-input-spending-secret"
            style={styles.input}
            value={spendingSecret}
            onChangeText={setSpendingSecret}
            keyboardType="numeric"
          />
        </View>

        <View style={styles.inputContainer}>
          <Text style={styles.label}>nullifier_secret</Text>
          <TextInput
            testID="deposit-input-nullifier-secret"
            style={styles.input}
            value={nullifierSecret}
            onChangeText={setNullifierSecret}
            keyboardType="numeric"
          />
        </View>

        <View style={styles.inputContainer}>
          <Text style={styles.label}>amount</Text>
          <TextInput
            testID="deposit-input-amount"
            style={styles.input}
            value={amount}
            onChangeText={setAmount}
            keyboardType="numeric"
          />
        </View>

        <View style={styles.inputContainer}>
          <Text style={styles.label}>receiver</Text>
          <TextInput
            testID="deposit-input-receiver"
            style={styles.input}
            value={receiver}
            onChangeText={setReceiver}
            keyboardType="numeric"
          />
        </View>

        <Button title="Generate Deposit Proof" onPress={() => genProof()} disabled={isBusy} />
        <Button title="Verify Deposit Proof" onPress={() => verifyProof()} disabled={isBusy} />

        {errorText ? (
          <>
            <Text style={styles.sectionLabel}>Error:</Text>
            <Text testID="deposit-error-output" style={styles.output}>
              {errorText}
            </Text>
          </>
        ) : null}

        <Text style={styles.sectionLabel}>Proof is Valid:</Text>
        <Text testID="deposit-valid-output" style={styles.output}>
          {isValid}
        </Text>

        <Text style={styles.sectionLabel}>Public Signals:</Text>
        <ScrollView style={styles.outputScroll} nestedScrollEnabled>
          <Text testID="deposit-inputs-output" style={styles.output}>
            {JSON.stringify(inputs)}
          </Text>
        </ScrollView>

        <Text style={styles.sectionLabel}>Proof:</Text>
        <ScrollView style={styles.outputScroll} nestedScrollEnabled>
          <Text testID="deposit-proof-output" style={styles.output}>
            {JSON.stringify(proof)}
          </Text>
        </ScrollView>
      </ScrollView>
    </View>
  );
}

const stylesVars = {
  violet: 'rgba(167, 139, 250, 0.95)',
  text: 'rgba(255, 255, 255, 0.9)',
};

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
  scroll: {
    flex: 1,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  backText: {
    color: stylesVars.text,
    fontSize: 16,
    fontWeight: '600',
  },
  headerTitle: {
    color: stylesVars.text,
    fontSize: 16,
    fontWeight: '700',
    letterSpacing: 0.3,
  },
  headerRightSpacer: {
    width: 40,
  },
  loadingOverlay: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    zIndex: 10,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 12,
    backgroundColor: 'rgba(0, 0, 0, 0.55)',
    padding: 20,
  },
  loadingOverlayText: {
    color: stylesVars.text,
    fontSize: 14,
    fontWeight: '700',
    letterSpacing: 0.2,
  },
  input: {
    height: 40,
    borderColor: 'rgba(255, 255, 255, 0.18)',
    borderWidth: 1,
    flex: 1,
    paddingHorizontal: 10,
    color: 'rgba(255, 255, 255, 0.92)',
    backgroundColor: 'rgba(255, 255, 255, 0.04)',
    borderRadius: 10,
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 10,
    gap: 10,
  },
  label: {
    fontSize: 14,
    color: stylesVars.text,
    width: 130,
  },
  outputScroll: {
    maxHeight: 150,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.14)',
    marginBottom: 10,
    borderRadius: 10,
  },
  output: {
    fontSize: 14,
    padding: 10,
    color: 'rgba(255, 255, 255, 0.85)',
  },
  proofContainer: {
    padding: 10,
  },
  sectionLabel: {
    color: stylesVars.text,
    marginTop: 6,
  },
});
