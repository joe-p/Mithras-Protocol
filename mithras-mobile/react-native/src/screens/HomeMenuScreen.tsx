import { Pressable, StyleSheet, Text, View } from 'react-native';

type Props = {
  onDeposit: () => void;
  onSpend: () => void;
  onMultiplier: () => void;
};

function MenuButton({ label, onPress }: { label: string; onPress?: () => void }) {
  return (
    <Pressable
      accessibilityRole="button"
      style={({ pressed }) => [styles.button, pressed && styles.buttonPressed]}
      onPress={onPress}
    >
      <Text style={styles.buttonText}>{label}</Text>
    </Pressable>
  );
}

export function HomeMenuScreen({ onDeposit, onSpend, onMultiplier }: Props) {
  return (
    <View style={styles.container}>
      <View style={styles.titleCorner}>
        <Text style={styles.title}>Mithras</Text>
      </View>
      <View style={styles.card}>
        <MenuButton label="Deposit funds into Mithras" onPress={onDeposit} />
        <MenuButton label="Send funds" onPress={onSpend} />
        <MenuButton label="Multiplier" onPress={onMultiplier} />
        <MenuButton label="Withdraw out of Mithras" />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
  },
  titleCorner: {
    position: 'absolute',
    top: 16,
    left: 18,
  },
  title: {
    color: 'rgba(167, 139, 250, 0.95)',
    fontSize: 30,
    fontWeight: '800',
    letterSpacing: 2.5,
    textShadowColor: 'rgba(167, 139, 250, 0.55)',
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 18,
  },
  card: {
    width: '100%',
    maxWidth: 420,
    gap: 12,
  },
  button: {
    borderRadius: 14,
    paddingVertical: 14,
    paddingHorizontal: 16,
    backgroundColor: 'rgba(255, 255, 255, 0.06)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.10)',
  },
  buttonPressed: {
    backgroundColor: 'rgba(255, 255, 255, 0.10)',
  },
  buttonText: {
    color: 'rgba(255, 255, 255, 0.92)',
    fontSize: 16,
    fontWeight: '600',
    letterSpacing: 0.2,
  },
});
