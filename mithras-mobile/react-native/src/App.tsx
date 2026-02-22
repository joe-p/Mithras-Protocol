import { useState } from 'react';
import { StyleSheet, View } from 'react-native';

import { AppSafeArea } from './components/AppSafeArea';
import { SpaceBackground } from './components/SpaceBackground';
import { HomeMenuScreen } from './screens/HomeMenuScreen';
import { DepositProofScreen } from './screens/proofs/DepositProofScreen';
import { MultiplierProofScreen } from './screens/proofs/MultiplierProofScreen';
import { SpendProofScreen } from './screens/proofs/SpendProofScreen';

type Route = 'menu' | 'deposit' | 'spend' | 'multiplier';

export default function App() {
  const [route, setRoute] = useState<Route>('menu');

  return (
    <AppSafeArea>
      <View style={styles.root}>
        <SpaceBackground />
        <View style={styles.container}>
          {route === 'menu' ? (
            <HomeMenuScreen
              onDeposit={() => setRoute('deposit')}
              onSpend={() => setRoute('spend')}
              onMultiplier={() => setRoute('multiplier')}
            />
          ) : route === 'deposit' ? (
            <DepositProofScreen onBack={() => setRoute('menu')} />
          ) : route === 'multiplier' ? (
            <MultiplierProofScreen onBack={() => setRoute('menu')} />
          ) : (
            <SpendProofScreen onBack={() => setRoute('menu')} />
          )}
        </View>
      </View>
    </AppSafeArea>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
  container: {
    flex: 1,
    alignItems: 'stretch',
    justifyContent: 'center',
  },
});
