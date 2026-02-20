import { useState } from 'react';
import { StyleSheet, View } from 'react-native';

import { AppSafeArea } from './components/AppSafeArea';
import { SpaceBackground } from './components/SpaceBackground';
import { CircomProofScreen } from './screens/CircomProofScreen';
import { HomeMenuScreen } from './screens/HomeMenuScreen';

type Route = 'menu' | 'deposit';

export default function App() {
  const [route, setRoute] = useState<Route>('menu');

  return (
    <AppSafeArea>
      <View style={styles.root}>
        <SpaceBackground />
        <View style={styles.container}>
          {route === 'menu' ? (
            <HomeMenuScreen onDeposit={() => setRoute('deposit')} />
          ) : (
            <CircomProofScreen onBack={() => setRoute('menu')} />
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
