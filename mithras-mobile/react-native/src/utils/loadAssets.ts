import { Platform } from 'react-native';
import RNFS from 'react-native-fs';

export async function loadAssets(fileName: string, options?: { force?: boolean }): Promise<string> {
  const filePath = `${RNFS.DocumentDirectoryPath}/${fileName}`;
  const force = options?.force === true;
  const fileExists = await RNFS.exists(filePath);

  if (force && fileExists) {
    try {
      await RNFS.unlink(filePath);
    } catch (error) {
      console.error('Error deleting cached file:', error);
    }
  }

  if (force || !fileExists) {
    try {
      let sourcePath = '';

      if (Platform.OS === 'android') {
        sourcePath = `custom/${fileName}`;
        await RNFS.copyFileAssets(sourcePath, filePath);
      } else {
        const candidates = [
          `${RNFS.MainBundlePath}/${fileName}`,
          `${RNFS.MainBundlePath}/assets/keys/${fileName}`,
          `${RNFS.MainBundlePath}/custom/${fileName}`,
        ];

        let lastError: unknown = undefined;
        for (const candidate of candidates) {
          try {
            sourcePath = candidate;
            await RNFS.copyFile(candidate, filePath);
            lastError = undefined;
            break;
          } catch (error) {
            lastError = error;
          }
        }

        if (lastError) {
          throw lastError;
        }
      }
    } catch (error) {
      console.error('Error copying file:', error);
      throw error;
    }
  }

  return filePath;
}
