import { Platform } from 'react-native';
import RNFS from 'react-native-fs';

export async function loadAssets(fileName: string): Promise<string> {
  const filePath = `${RNFS.DocumentDirectoryPath}/${fileName}`;
  const fileExists = await RNFS.exists(filePath);

  if (!fileExists) {
    try {
      let sourcePath = '';

      if (Platform.OS === 'android') {
        sourcePath = `custom/${fileName}`;
        await RNFS.copyFileAssets(sourcePath, filePath);
      } else {
        sourcePath = `${RNFS.MainBundlePath}/${fileName}`;
        await RNFS.copyFile(sourcePath, filePath);
      }
    } catch (error) {
      console.error('Error copying file:', error);
      throw error;
    }
  }

  return filePath;
}
