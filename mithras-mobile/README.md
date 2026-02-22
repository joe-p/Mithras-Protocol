# Mithras Mobile

Welcome to Mithras Mobile, the mobile version of the Mithras Protocol created by joe-p.

Mithras Protocol is a privacy protocol built on Algorand, using ZK-SNARKs and Stealth Addresses.

## Introduction

Mithras Mobile was built using [ZK Mopro](https://zkmopro.org), the Mobile Proving toolkit that allows you to generate and verify ZK-SNARKs on your phone.

In order to make things work with Mopro, Mithras Mobile is relies on Groth16 over BN254. The hope is to one day be able to do Groth16 over BLS12-381, or even better, Plonk over BLS12-381.

## How to Run App

Navigate into `react-native` and run `npm install && npm run ios` for iOS, or `npm install && npm run android` for Android. It might be that the Metro bundler is not started automatically, in which case you need to (in a new terminal window/tab) run `npm run start`.

## Packages & Mithras Mobile

Mithras Mobile needs the appropriate .wasm and .zkey files. For now it bundles them (deposit{.zkey, .wasm}, spend{.zkey, .wasm}) from test-vectors/circom when you build the react native project.

Note that `deposit` (deposit Algo funds into the privacy set of Mithras) and `spend` (send private Algo funds to someone's stealth address) are currently the only ZK-SNARKs available to generate. In the future `withdraw` (withdraw funds out of the privacy set into public Algorand) will also be added.

## Updating the Project with New ZK stuff

**Note: The following guide can be improved...**

This should only be done in case you've made changes to the ZK circuit itself or the Powers-of-Tau ceremony.

1) Navigate to {root}/packages/mithras-contracts-and-circuits.
2) Run `pnpm run build && pnpm run test`. (The crucial part is that hte build command runs the zkey.sh script, which produces the .wasm and .zkey files necesary. But it is good to build the Algorand contracts files and the full test suite to make sure things are OK.)
3) Run:
     ```
     mv /circuit/deposit_test.zkey ../../mithras-mobile/test-vectors/deposit.zkey
     mv /circuit/spend_test.zkey ../../mithras-mobile/test-vectors/spend.zkey
     mv /circuit/deposit_js/deposit.wasm ../../mithras-mobile/test-vectors/deposit.wasm
     mv /circuit/spend_js/spend.wasm ../../mithras-mobile/test-vectors/spend.wasm
     ```
4) Navigate to {root}/mithras-mobile/react-native
5) For iOS: `npm install && npm run ubrn:ios && npm run ios` (switch ios for android as needed)
6) If needed, open up a new terminal and run `npm run start` to run the Metro Bundler.


The `{root}/mithras-mobile/react-native/MoproReactNativeBindings` folder contains the bindings allowing `generateCircomProof()` and `verifyCircomProof()` to be called from React Native. It has been built for the `debug` target.

It might come to be that you wish to change that. Then you can install the `mopro` cli tool (`cargo install mopro-cli`) and call `mopro build` from within `{root}/mithras-mobile`. 

Instead of `debug` you can pick `release` build mode. Stick to `react-native` and the relevant platforms (currently: `aarch64-apple-ios` (iOS phone), `aarch64-apple-ios-sim`(iOS Simulator), `✔ x86_64-linux-android` and `✔ aarch64-linux-android`).

Afterwards, a new `MoproReactNativeBindings` will be created. Use `mv MoproReactNativeBindings react-native/MoproReactNativeBindings`.

Then open `react-native/MoproReactNativeBindings/package.json` and replace the script section with the following:

```
    "scripts": {
        "ubrn:ios": "ubrn build ios --and-generate --release && (cd ../ios && pod install)",
        "ubrn:android": "ubrn build android --and-generate --release --targets aarch64-linux-android",
        "test": "jest",
        "typecheck": "tsc",
        "lint": "eslint \"**/*.{js,ts,tsx}\"",
        "clean": "del-cli android/build ../android/build ../android/app/build ../ios/build lib",
        "prepare": "bob build",
        "release": "release-it --only-version"
    },
```

Basically, we replace `example/` with `../`, since `MoproReactNativeBindings` is placed inside `react-native`, in accordance with [the guide](https://zkmopro.org/docs/setup/react-native-setup).

