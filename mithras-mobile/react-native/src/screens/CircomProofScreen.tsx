import { useState } from 'react';
import {
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

import { loadAssets } from '../utils/loadAssets';

type Props = {
  onBack?: () => void;
};

export function CircomProofScreen({ onBack }: Props) {
  const [a, setA] = useState('3');
  const [b, setB] = useState('4');
  const [inputs, setInputs] = useState<string[]>([]);
  const [proof, setProof] = useState<CircomProof>({
    a: { x: '', y: '', z: '' },
    b: { x: [], y: [], z: [] },
    c: { x: '', y: '', z: '' },
    protocol: '',
    curve: '',
  });
  const [isValid, setIsValid] = useState<string>('');

  async function genProof(): Promise<void> {
    const circuitInputs = {
      a: [a],
      b: [b],
    };

    if (Platform.OS === 'android' || Platform.OS === 'ios') {
      const filePath = await loadAssets('multiplier2_final.zkey');

      try {
        const res: CircomProofResult = await generateCircomProof(
          filePath.replace('file://', ''),
          JSON.stringify(circuitInputs),
          ProofLib.Arkworks
        );
        setProof(res.proof);
        setInputs(res.inputs);
      } catch (error) {
        console.error('Error generating proof:', error);
      }
    }
  }

  async function verifyProof(): Promise<void> {
    if (Platform.OS === 'android' || Platform.OS === 'ios') {
      const filePath = await loadAssets('multiplier2_final.zkey');

      try {
        const circomProofResult: CircomProofResult = {
          proof: proof,
          inputs: inputs,
        };

        const res: boolean = await verifyCircomProof(
          filePath.replace('file://', ''),
          circomProofResult,
          ProofLib.Arkworks
        );
        setIsValid(res.toString());
      } catch (error) {
        console.error('Error verifying proof:', error);
      }
    }
  }

  return (
    <View style={styles.proofContainer} testID="circom-proof-container">
      {onBack ? (
        <View style={styles.header}>
          <Pressable accessibilityRole="button" onPress={onBack} hitSlop={10}>
            <Text style={styles.backText}>Back</Text>
          </Pressable>
          <Text style={styles.headerTitle}>Circom</Text>
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
      />
      <Button
        testID="circom-verify-proof-button"
        title="Verify Circom Proof"
        onPress={() => verifyProof()}
      />
      <Text style={styles.sectionLabel}>Proof is Valid:</Text>
      <Text testID="circom-valid-output" style={styles.output}>
        {isValid}
      </Text>
      <Text style={styles.sectionLabel}>Public Signals:</Text>
      <ScrollView style={styles.outputScroll}>
        <Text testID="circom-inputs-output" style={styles.output}>
          {JSON.stringify(inputs)}
        </Text>
      </ScrollView>
      <Text style={styles.sectionLabel}>Proof:</Text>
      <ScrollView style={styles.outputScroll}>
        <Text testID="circom-proof-output" style={styles.output}>
          {JSON.stringify(proof)}
        </Text>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  backText: {
    color: 'rgba(255, 255, 255, 0.9)',
    fontSize: 16,
    fontWeight: '600',
  },
  headerTitle: {
    color: 'rgba(255, 255, 255, 0.9)',
    fontSize: 16,
    fontWeight: '700',
    letterSpacing: 0.3,
  },
  headerRightSpacer: {
    width: 40,
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
    color: 'rgba(255, 255, 255, 0.9)',
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
    color: 'rgba(255, 255, 255, 0.9)',
    marginTop: 6,
  },
});
