import { useEffect, useMemo, useRef } from 'react';
import {
  Animated,
  Dimensions,
  Easing,
  StyleSheet,
  View,
  type ViewStyle,
} from 'react-native';

type Star = {
  key: string;
  left: number;
  top: number;
  size: number;
  baseOpacity: number;
  twinkleDurationMs: number;
  twinkleDelayMs: number;
  driftDurationMs: number;
  driftDelayMs: number;
  driftPx: number;
};

function mulberry32(seed: number) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

export function SpaceBackground({ style }: { style?: ViewStyle }) {
  const { width, height } = Dimensions.get('window');

  const stars = useMemo<Star[]>(() => {
    const seed = 1337;
    const rand = mulberry32(seed);

    const count = clamp(Math.floor((width * height) / 14000), 70, 160);

    return Array.from({ length: count }).map((_, i) => {
      const roll = rand();
      const size = roll < 0.06 ? 3 : roll < 0.20 ? 2 : 1;
      const baseOpacity = 0.12 + rand() * 0.28;

      return {
        key: `star-${i}`,
        left: rand() * width,
        top: rand() * height,
        size,
        baseOpacity,
        twinkleDurationMs: 1800 + Math.floor(rand() * 2200),
        twinkleDelayMs: Math.floor(rand() * 1800),
        driftDurationMs: 5000 + Math.floor(rand() * 5000),
        driftDelayMs: Math.floor(rand() * 2000),
        driftPx: (rand() - 0.5) * 10,
      };
    });
  }, [width, height]);

  const twinkles = useRef(stars.map(() => new Animated.Value(0))).current;
  const drifts = useRef(stars.map(() => new Animated.Value(0))).current;

  useEffect(() => {
    const animations: Animated.CompositeAnimation[] = [];

    stars.forEach((star, idx) => {
      const tw = twinkles[idx];
      const dr = drifts[idx];

      const twinkle = Animated.loop(
        Animated.sequence([
          Animated.delay(star.twinkleDelayMs),
          Animated.timing(tw, {
            toValue: 1,
            duration: star.twinkleDurationMs,
            easing: Easing.inOut(Easing.quad),
            useNativeDriver: true,
          }),
          Animated.timing(tw, {
            toValue: 0,
            duration: star.twinkleDurationMs,
            easing: Easing.inOut(Easing.quad),
            useNativeDriver: true,
          }),
        ])
      );

      const drift = Animated.loop(
        Animated.sequence([
          Animated.delay(star.driftDelayMs),
          Animated.timing(dr, {
            toValue: 1,
            duration: star.driftDurationMs,
            easing: Easing.inOut(Easing.quad),
            useNativeDriver: true,
          }),
          Animated.timing(dr, {
            toValue: 0,
            duration: star.driftDurationMs,
            easing: Easing.inOut(Easing.quad),
            useNativeDriver: true,
          }),
        ])
      );

      animations.push(twinkle, drift);
    });

    animations.forEach((a) => a.start());

    return () => {
      animations.forEach((a) => a.stop());
    };
  }, [drifts, stars, twinkles]);

  const planet1 = useMemo(() => {
    const size = 360;
    return {
      size,
      left: -110,
      top: -170,
      cx: -110 + size / 2,
      cy: -170 + size / 2,
    };
  }, []);

  const planet2 = useMemo(() => {
    const size = 420;
    const left = width - 260;
    const top = height - 290;
    return {
      size,
      left,
      top,
      cx: left + size / 2,
      cy: top + size / 2,
    };
  }, [height, width]);

  const moonRotations = useRef([
    new Animated.Value(0),
    new Animated.Value(0),
    new Animated.Value(0),
    new Animated.Value(0),
  ]).current;

  useEffect(() => {
    const loops = moonRotations.map((v, idx) =>
      Animated.loop(
        Animated.timing(v, {
          toValue: 1,
          duration: 9000 + idx * 2200,
          easing: Easing.linear,
          useNativeDriver: true,
        })
      )
    );

    loops.forEach((a) => a.start());
    return () => loops.forEach((a) => a.stop());
  }, [moonRotations]);

  return (
    <View pointerEvents="none" style={[styles.container, style]}>
      <View style={styles.base} />

      <View
        style={[
          styles.glow,
          {
            left: planet1.left,
            top: planet1.top,
            width: planet1.size,
            height: planet1.size,
            borderRadius: planet1.size,
            backgroundColor: 'rgba(56, 189, 248, 0.06)',
          },
        ]}
      />
      <View
        style={[
          styles.glow,
          {
            left: planet2.left,
            top: planet2.top,
            width: planet2.size,
            height: planet2.size,
            borderRadius: planet2.size,
            backgroundColor: 'rgba(167, 139, 250, 0.05)',
          },
        ]}
      />

      {stars.map((star, idx) => {
        const tw = twinkles[idx];
        const dr = drifts[idx];

        const opacity = tw.interpolate({
          inputRange: [0, 1],
          outputRange: [star.baseOpacity, 0.95],
        });

        const translateY = dr.interpolate({
          inputRange: [0, 1],
          outputRange: [0, star.driftPx],
        });

        return (
          <Animated.View
            key={star.key}
            style={[
              styles.star,
              {
                left: star.left,
                top: star.top,
                width: star.size,
                height: star.size,
                borderRadius: star.size,
                opacity,
                transform: [{ translateY }],
              },
            ]}
          />
        );
      })}

      {/* Moons around planet 1 */}
      <Animated.View
        style={[
          styles.moon,
          {
            left: planet1.cx,
            top: planet1.cy,
            width: 10,
            height: 10,
            borderRadius: 10,
            opacity: 0.55,
            backgroundColor: 'rgba(255, 255, 255, 0.95)',
            transform: [
              { translateX: -5 },
              { translateY: -5 },
              {
                rotate: moonRotations[0].interpolate({
                  inputRange: [0, 1],
                  outputRange: ['0deg', '360deg'],
                }),
              },
              { translateX: 68 },
            ],
          },
        ]}
      />
      <Animated.View
        style={[
          styles.moon,
          {
            left: planet1.cx,
            top: planet1.cy,
            width: 6,
            height: 6,
            borderRadius: 6,
            opacity: 0.35,
            backgroundColor: 'rgba(167, 139, 250, 0.95)',
            transform: [
              { translateX: -3 },
              { translateY: -3 },
              {
                rotate: moonRotations[1].interpolate({
                  inputRange: [0, 1],
                  outputRange: ['0deg', '360deg'],
                }),
              },
              { translateX: 98 },
            ],
          },
        ]}
      />

      {/* Moons around planet 2 */}
      <Animated.View
        style={[
          styles.moon,
          {
            left: planet2.cx,
            top: planet2.cy,
            width: 12,
            height: 12,
            borderRadius: 12,
            opacity: 0.45,
            backgroundColor: 'rgba(255, 255, 255, 0.9)',
            transform: [
              { translateX: -6 },
              { translateY: -6 },
              {
                rotate: moonRotations[2].interpolate({
                  inputRange: [0, 1],
                  outputRange: ['0deg', '360deg'],
                }),
              },
              { translateX: 82 },
            ],
          },
        ]}
      />
      <Animated.View
        style={[
          styles.moon,
          {
            left: planet2.cx,
            top: planet2.cy,
            width: 7,
            height: 7,
            borderRadius: 7,
            opacity: 0.32,
            backgroundColor: 'rgba(56, 189, 248, 0.9)',
            transform: [
              { translateX: -3.5 },
              { translateY: -3.5 },
              {
                rotate: moonRotations[3].interpolate({
                  inputRange: [0, 1],
                  outputRange: ['0deg', '360deg'],
                }),
              },
              { translateX: 118 },
            ],
          },
        ]}
      />

      <View style={styles.vignette} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    ...StyleSheet.absoluteFillObject,
  },
  base: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: '#05060A',
  },
  glow: {
    position: 'absolute',
  },
  star: {
    position: 'absolute',
    backgroundColor: 'rgba(255, 255, 255, 1)',
  },
  moon: {
    position: 'absolute',
  },
  vignette: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(0, 0, 0, 0.25)',
  },
});
