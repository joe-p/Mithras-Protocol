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

export function MultiplierProofScreen({ onBack }: Props) {
  const [a, setA] = useState('3');
  const [b, setB] = useState('4');

  const zkeyName = 'multiplier2_final.zkey';

  const [inputs, setInputs] = useState<string[]>([]);
  const [proof, setProof] = useState<CircomProof>({
    a: { x: '', y: '', z: '' },
    b: { x: [], y: [], z: [] },
    c: { x: '', y: '', z: '' },
    protocol: '',
    curve: '',
  });
  const [isValid, setIsValid] = useState<string>('');
  const [isBusy, setIsBusy] = useState(false);
  const lastResultRef = useRef<CircomProofResult | null>(null);

  async function genProof(): Promise<void> {
    setIsValid('');
    setIsBusy(true);

    const circuitInputs = {
      a: [a],
      b: [b],
    };

    if (Platform.OS === 'android' || Platform.OS === 'ios') {
      const filePath = await loadAssets(zkeyName, { force: true });

      try {
        const res: CircomProofResult = await generateCircomProof(
          filePath.replace('file://', ''),
          JSON.stringify(circuitInputs),
          ProofLib.Arkworks
        );
        lastResultRef.current = res;
        setProof(res.proof);
        setInputs(res.inputs);
      } catch (error) {
        console.error('Error generating proof:', error);
      } finally {
        setIsBusy(false);
      }
    }
  }

  async function verifyProof(): Promise<void> {
    setIsBusy(true);
    if (Platform.OS === 'android' || Platform.OS === 'ios') {
      const filePath = await loadAssets(zkeyName, { force: true });

      try {
        const circomProofResult: CircomProofResult =
          lastResultRef.current ?? {
            proof: proof,
            inputs: inputs,
          };

        if (!circomProofResult.inputs?.length) {
          return;
        }

        const res: boolean = await verifyCircomProof(
          filePath.replace('file://', ''),
          circomProofResult,
          ProofLib.Arkworks
        );
        setIsValid(res.toString());
      } catch (error) {
        console.error('Error verifying proof:', error);
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
        testID="circom-proof-container"
      >
        {onBack ? (
          <View style={styles.header}>
            <Pressable accessibilityRole="button" onPress={onBack} hitSlop={10}>
              <Text style={styles.backText}>Back</Text>
            </Pressable>
            <Text style={styles.headerTitle}>Multiplier</Text>
            <View style={styles.headerRightSpacer} />
          </View>
        ) : null}

        <View style={styles.inputContainer}>
          <Text style={styles.label}>a</Text>
          <TextInput
            testID="circom-input-a"
            style={styles.input}
            placeholder="Enter value for a"
            value={a}
            onChangeText={setA}
            keyboardType="numeric"
          />
        </View>
        <View style={styles.inputContainer}>
          <Text style={styles.label}>b</Text>
          <TextInput
            testID="circom-input-b"
            style={styles.input}
            placeholder="Enter value for b"
            value={b}
            onChangeText={setB}
            keyboardType="numeric"
          />
        </View>
        <Button
          testID="circom-gen-proof-button"
          title="Generate Circom Proof"
          onPress={() => genProof()}
          disabled={isBusy}
        />
        <Button
          testID="circom-verify-proof-button"
          title="Verify Circom Proof"
          onPress={() => verifyProof()}
          disabled={isBusy}
        />

        <Text style={styles.sectionLabel}>Curve / Protocol:</Text>
        <Text testID="circom-curve-output" style={styles.output}>
          {String(proof.curve || '')} / {String(proof.protocol || '')}
        </Text>

        <Text style={styles.sectionLabel}>Proof is Valid:</Text>
        <Text testID="circom-valid-output" style={styles.output}>
          {isValid}
        </Text>
        <Text style={styles.sectionLabel}>Public Signals:</Text>
        <ScrollView style={styles.outputScroll} nestedScrollEnabled>
          <Text testID="circom-inputs-output" style={styles.output}>
            {JSON.stringify(inputs)}
          </Text>
        </ScrollView>
        <Text style={styles.sectionLabel}>Proof:</Text>
        <ScrollView style={styles.outputScroll} nestedScrollEnabled>
          <Text testID="circom-proof-output" style={styles.output}>
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
  },
  label: {
    fontSize: 16,
    marginRight: 10,
    color: stylesVars.text,
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
