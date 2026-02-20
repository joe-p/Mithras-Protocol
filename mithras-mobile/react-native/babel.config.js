const path = require('path');
const { getConfig } = require('react-native-builder-bob/babel-config');
const pkg = require('./MoproReactNativeBindings/package.json');

const root = path.resolve(__dirname, 'MoproReactNativeBindings');

module.exports = getConfig(
  {
    presets: ['module:@react-native/babel-preset'],
  },
  { root, pkg }
);
