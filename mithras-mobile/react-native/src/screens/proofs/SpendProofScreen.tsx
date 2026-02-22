import { useMemo, useRef, useState } from 'react';
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

function depth16Zeros(): string[] {
  return Array.from({ length: 16 }, () => '0');
}

export function SpendProofScreen({ onBack }: Props) {
  const [fee, setFee] = useState('7');

  const [utxoSpender, setUtxoSpender] = useState('999');

  const [utxoAmount, setUtxoAmount] = useState('1000');
  const [utxoNullifierSecret, setUtxoNullifierSecret] = useState('222');
  const [utxoSpendingSecret, setUtxoSpendingSecret] = useState('111');

  const [out0Amount, setOut0Amount] = useState('500');
  const [out0Receiver, setOut0Receiver] = useState('1234');
  const [out0SpendingSecret, setOut0SpendingSecret] = useState('333');
  const [out0NullifierSecret, setOut0NullifierSecret] = useState('444');

  const [out1Amount, setOut1Amount] = useState('493');
  const [out1Receiver, setOut1Receiver] = useState('5678');
  const [out1SpendingSecret, setOut1SpendingSecret] = useState('555');
  const [out1NullifierSecret, setOut1NullifierSecret] = useState('666');

  const defaultPathSelectors = useMemo(() => depth16Zeros(), []);
  const defaultUtxoPath = useMemo(() => depth16Zeros(), []);

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
      fee,
      utxo_spender: utxoSpender,

      utxo_amount: utxoAmount,
      utxo_nullifier_secret: utxoNullifierSecret,
      utxo_spending_secret: utxoSpendingSecret,

      out0_amount: out0Amount,
      out0_receiver: out0Receiver,
      out0_spending_secret: out0SpendingSecret,
      out0_nullifier_secret: out0NullifierSecret,

      out1_amount: out1Amount,
      out1_receiver: out1Receiver,
      out1_spending_secret: out1SpendingSecret,
      out1_nullifier_secret: out1NullifierSecret,

      path_selectors: defaultPathSelectors,
      utxo_path: defaultUtxoPath,
    };

    if (Platform.OS === 'android' || Platform.OS === 'ios') {
      const filePath = await loadAssets('spend.zkey', { force: true });
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
        (await loadAssets('spend_test.zkey', { force: true })).replace('file://', '');
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
        testID="spend-proof-container"
      >
        {onBack ? (
          <View style={styles.header}>
            <Pressable accessibilityRole="button" onPress={onBack} hitSlop={10}>
              <Text style={styles.backText}>Back</Text>
            </Pressable>
            <Text style={styles.headerTitle}>Spend</Text>
            <View style={styles.headerRightSpacer} />
          </View>
        ) : null}

        <View style={styles.inputContainer}>
          <Text style={styles.label}>fee</Text>
          <TextInput
            testID="spend-input-fee"
            style={styles.input}
            value={fee}
            onChangeText={setFee}
            keyboardType="numeric"
          />
        </View>

        <View style={styles.inputContainer}>
          <Text style={styles.label}>utxo_spender</Text>
          <TextInput
            testID="spend-input-utxo-spender"
            style={styles.input}
            value={utxoSpender}
            onChangeText={setUtxoSpender}
            keyboardType="numeric"
          />
        </View>

        <Text style={styles.groupTitle}>UTXO</Text>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>utxo_amount</Text>
          <TextInput
            testID="spend-input-utxo-amount"
            style={styles.input}
            value={utxoAmount}
            onChangeText={setUtxoAmount}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>utxo_nullifier_secret</Text>
          <TextInput
            testID="spend-input-utxo-nullifier-secret"
            style={styles.input}
            value={utxoNullifierSecret}
            onChangeText={setUtxoNullifierSecret}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>utxo_spending_secret</Text>
          <TextInput
            testID="spend-input-utxo-spending-secret"
            style={styles.input}
            value={utxoSpendingSecret}
            onChangeText={setUtxoSpendingSecret}
            keyboardType="numeric"
          />
        </View>

        <Text style={styles.groupTitle}>Out0</Text>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>out0_amount</Text>
          <TextInput
            testID="spend-input-out0-amount"
            style={styles.input}
            value={out0Amount}
            onChangeText={setOut0Amount}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>out0_receiver</Text>
          <TextInput
            testID="spend-input-out0-receiver"
            style={styles.input}
            value={out0Receiver}
            onChangeText={setOut0Receiver}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>out0_spending_secret</Text>
          <TextInput
            testID="spend-input-out0-spending-secret"
            style={styles.input}
            value={out0SpendingSecret}
            onChangeText={setOut0SpendingSecret}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>out0_nullifier_secret</Text>
          <TextInput
            testID="spend-input-out0-nullifier-secret"
            style={styles.input}
            value={out0NullifierSecret}
            onChangeText={setOut0NullifierSecret}
            keyboardType="numeric"
          />
        </View>

        <Text style={styles.groupTitle}>Out1</Text>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>out1_amount</Text>
          <TextInput
            testID="spend-input-out1-amount"
            style={styles.input}
            value={out1Amount}
            onChangeText={setOut1Amount}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>out1_receiver</Text>
          <TextInput
            testID="spend-input-out1-receiver"
            style={styles.input}
            value={out1Receiver}
            onChangeText={setOut1Receiver}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>out1_spending_secret</Text>
          <TextInput
            testID="spend-input-out1-spending-secret"
            style={styles.input}
            value={out1SpendingSecret}
            onChangeText={setOut1SpendingSecret}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>out1_nullifier_secret</Text>
          <TextInput
            testID="spend-input-out1-nullifier-secret"
            style={styles.input}
            value={out1NullifierSecret}
            onChangeText={setOut1NullifierSecret}
            keyboardType="numeric"
          />
        </View>

        <Button title="Generate Spend Proof" onPress={() => genProof()} disabled={isBusy} />
        <Button title="Verify Spend Proof" onPress={() => verifyProof()} disabled={isBusy} />

        {errorText ? (
          <>
            <Text style={styles.sectionLabel}>Error:</Text>
            <Text testID="spend-error-output" style={styles.output}>
              {errorText}
            </Text>
          </>
        ) : null}

        <Text style={styles.sectionLabel}>Proof is Valid:</Text>
        <Text testID="spend-valid-output" style={styles.output}>
          {isValid}
        </Text>

        <Text style={styles.sectionLabel}>Public Signals:</Text>
        <ScrollView style={styles.outputScroll} nestedScrollEnabled>
          <Text testID="spend-inputs-output" style={styles.output}>
            {JSON.stringify(inputs)}
          </Text>
        </ScrollView>

        <Text style={styles.sectionLabel}>Proof:</Text>
        <ScrollView style={styles.outputScroll} nestedScrollEnabled>
          <Text testID="spend-proof-output" style={styles.output}>
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
  groupTitle: {
    color: stylesVars.text,
    fontSize: 14,
    fontWeight: '700',
    marginTop: 8,
    marginBottom: 6,
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
    width: 170,
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
