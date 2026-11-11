export interface HarvestedKeyItem {
  alias: string;
  keyType: 'AES' | 'SQLCIPHER_PASS' | 'TINK_KEYSET' | 'AUTH_TOKEN' | 'FIREBASE';
  value: string;
  sourceFile: string;
}

/**
 * Android shared_prefs XML Key Harvester.
 * Scans application shared preferences for SQLCipher passphrases and cryptographic keys.
 */
export class SharedPrefsKeyHarvester {
  public static harvestXml(xmlBuffer: Buffer, vfsPath: string): HarvestedKeyItem[] {
    const items: HarvestedKeyItem[] = [];
    const text = xmlBuffer.toString('utf8');

    // Match <string name="...">...</string>
    const stringRegex = /<string\s+name="([^"]+)">([^<]+)<\/string>/g;
    let match: RegExpExecArray | null;

    while ((match = stringRegex.exec(text)) !== null) {
      const name = match[1];
      const val = match[2];

      const lowerName = name.toLowerCase();

      if (lowerName.includes('sqlcipher') || lowerName.includes('db_key') || lowerName.includes('passphrase') || lowerName.includes('database_secret')) {
        items.push({
          alias: name,
          keyType: 'SQLCIPHER_PASS',
          value: val,
          sourceFile: vfsPath
        });
      } else if (lowerName.includes('tink') || lowerName.includes('keyset')) {
        items.push({
          alias: name,
          keyType: 'TINK_KEYSET',
          value: val,
          sourceFile: vfsPath
        });
      } else if (lowerName.includes('token') || lowerName.includes('auth') || lowerName.includes('session')) {
        items.push({
          alias: name,
          keyType: 'AUTH_TOKEN',
          value: val,
          sourceFile: vfsPath
        });
      }
    }

    return items;
  }
}
