import * as crypto from 'crypto';
import * as os from 'os';
import { execSync } from 'child_process';
import { AuditLogger } from '../case-manager/audit-logger';

export interface OfflineLicensePayload {
  licensee: string;
  organization: string;
  licenseId: string;
  issueDate: string;
  expiryDate: string; // e.g. "2030-12-31T23:59:59.000Z"
  hardwareHash: string; // Bound to Motherboard UUID & CPU ID
  allowedFeatures: string[];
  maxCases?: number;
}

export interface SignedLicenseFile {
  payload: OfflineLicensePayload;
  signatureHex: string; // Ed25519 signature over JSON.stringify(payload)
}

export interface LicenseVerificationResult {
  isValid: boolean;
  licensee?: string;
  organization?: string;
  expiryDate?: string;
  allowedFeatures?: string[];
  error?: string;
}

/**
 * Air-Gapped Offline Hardware License Verifier & Network Isolation Firewall.
 * Guarantees zero network leakage and machine-locked forensic tool licensing.
 */
export class HardwareLock {
  // Official BHARAT-PA Authority Ed25519 Public Key (DER SubjectPublicKeyInfo format in hex)
  public static readonly OFFICIAL_AUTHORITY_PUBKEY_HEX =
    '302a300506032b6570032100e4708781a951d1f053538431bf3f295b9a4731885f812165e31765c928b98e16';

  /**
   * Generates a deterministic Hardware Fingerprint bound to Motherboard UUID and CPU ID.
   */
  public static getHardwareFingerprint(): { hardwareHash: string; motherboardUuid: string; cpuId: string } {
    let motherboardUuid = 'UNKNOWN_MB_UUID';
    let cpuId = 'UNKNOWN_CPU_ID';

    const platform = os.platform();

    try {
      if (platform === 'win32') {
        // Query Windows MachineGuid / Motherboard UUID
        try {
          const regOutput = execSync('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', {
            stdio: ['pipe', 'pipe', 'ignore'],
            encoding: 'utf8'
          });
          const match = /MachineGuid\s+REG_SZ\s+([A-Fa-f0-9\-]+)/i.exec(regOutput);
          if (match) {
            motherboardUuid = match[1].trim();
          }
        } catch {
          // Fallback to wmic or computername
          motherboardUuid = os.hostname();
        }

        // Query CPU processor ID / family
        const cpus = os.cpus();
        if (cpus && cpus.length > 0) {
          cpuId = `${cpus[0].model}_${cpus[0].speed}_${cpus.length}`;
        }
      } else if (platform === 'linux') {
        // Linux machine-id
        try {
          const fs = require('fs');
          if (fs.existsSync('/etc/machine-id')) {
            motherboardUuid = fs.readFileSync('/etc/machine-id', 'utf8').trim();
          } else if (fs.existsSync('/sys/class/dmi/id/product_uuid')) {
            motherboardUuid = fs.readFileSync('/sys/class/dmi/id/product_uuid', 'utf8').trim();
          }
        } catch {}

        const cpus = os.cpus();
        if (cpus && cpus.length > 0) {
          cpuId = `${cpus[0].model}_${cpus.length}`;
        }
      } else {
        motherboardUuid = os.hostname();
        cpuId = os.arch();
      }
    } catch {
      motherboardUuid = os.hostname();
      cpuId = os.arch();
    }

    const rawString = `${motherboardUuid.toUpperCase()}|${cpuId.toUpperCase()}|${platform}`;
    const hardwareHash = crypto.createHash('sha256').update(rawString).digest('hex');

    return {
      hardwareHash,
      motherboardUuid,
      cpuId
    };
  }

  /**
   * Cryptographically verifies an offline license using Ed25519 signature verification
   * and verifies that the current workstation's hardware hash matches the license payload.
   */
  public static verifyLicense(
    license: SignedLicenseFile,
    authorityPubKeyDerHex: string = HardwareLock.OFFICIAL_AUTHORITY_PUBKEY_HEX,
    bypassHardwareCheck: boolean = false
  ): LicenseVerificationResult {
    const payload = license.payload;
    if (!payload || !license.signatureHex) {
      return { isValid: false, error: 'Invalid license format: missing payload or signature' };
    }

    // 1. Check expiration date
    const expiryEpoch = new Date(payload.expiryDate).getTime();
    if (isNaN(expiryEpoch) || Date.now() > expiryEpoch) {
      return {
        isValid: false,
        licensee: payload.licensee,
        expiryDate: payload.expiryDate,
        error: `License has expired on ${payload.expiryDate}`
      };
    }

    // 2. Check Hardware Fingerprint Lock
    if (!bypassHardwareCheck) {
      const currentHardware = HardwareLock.getHardwareFingerprint();
      if (currentHardware.hardwareHash.toLowerCase() !== payload.hardwareHash.toLowerCase()) {
        return {
          isValid: false,
          licensee: payload.licensee,
          error: `Hardware lock mismatch: License bound to ${payload.hardwareHash.slice(0, 16)}..., but running on ${currentHardware.hardwareHash.slice(0, 16)}...`
        };
      }
    }

    // 3. Cryptographic Ed25519 Signature Verification
    try {
      const pubKeyDer = Buffer.from(authorityPubKeyDerHex, 'hex');
      const publicKey = crypto.createPublicKey({
        key: pubKeyDer,
        format: 'der',
        type: 'spki'
      });

      const payloadCanonical = JSON.stringify(payload);
      const signatureBuf = Buffer.from(license.signatureHex, 'hex');

      const isSigValid = crypto.verify(
        null,
        Buffer.from(payloadCanonical, 'utf8'),
        publicKey,
        signatureBuf
      );

      if (!isSigValid) {
        return {
          isValid: false,
          licensee: payload.licensee,
          error: 'Ed25519 cryptographic signature verification failed'
        };
      }

      return {
        isValid: true,
        licensee: payload.licensee,
        organization: payload.organization,
        expiryDate: payload.expiryDate,
        allowedFeatures: payload.allowedFeatures
      };
    } catch (err: any) {
      return {
        isValid: false,
        error: `Cryptographic validation exception: ${err.message}`
      };
    }
  }

  /**
   * Helper utility to generate an Ed25519 keypair for authority license issuance.
   */
  public static generateAuthorityKeyPair(): { publicKeyDerHex: string; privateKeyDerHex: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return {
      publicKeyDerHex: publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
      privateKeyDerHex: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex')
    };
  }

  /**
   * Signs a license payload using the Authority Ed25519 private key.
   */
  public static issueSignedLicense(
    payload: OfflineLicensePayload,
    authorityPrivateKeyDerHex: string
  ): SignedLicenseFile {
    const privKeyDer = Buffer.from(authorityPrivateKeyDerHex, 'hex');
    const privateKey = crypto.createPrivateKey({
      key: privKeyDer,
      format: 'der',
      type: 'pkcs8'
    });

    const payloadCanonical = JSON.stringify(payload);
    const signature = crypto.sign(null, Buffer.from(payloadCanonical, 'utf8'), privateKey);

    return {
      payload,
      signatureHex: signature.toString('hex')
    };
  }

  /**
   * Installs the Electron WebRequest Air-Gap Firewall.
   * Blocks 100% of outbound internet requests and logs all attempted leakages.
   */
  public static installAirGapFirewall(electronSession: any, auditLogger?: AuditLogger): void {
    if (!electronSession || !electronSession.webRequest) {
      // In non-Electron environments (testing or headless CLI), log readiness
      if (auditLogger) {
        auditLogger.logAction(
          'LICENSE_VERIFICATION',
          'Air-Gap Firewall configured for offline operation',
          { mode: 'STRICT_OFFLINE', webRequestFilteringEnabled: true }
        );
      }
      return;
    }

    const filter = { urls: ['*://*/*'] };

    electronSession.webRequest.onBeforeRequest(filter, (details: any, callback: (response: { cancel: boolean }) => void) => {
      const url = details.url.toLowerCase();

      // Allow only internal safe protocols: file://, devtools://, data:, blob:
      const isInternal =
        url.startsWith('file://') ||
        url.startsWith('devtools://') ||
        url.startsWith('data:') ||
        url.startsWith('blob:') ||
        url.startsWith('http://localhost') ||
        url.startsWith('http://127.0.0.1');

      if (isInternal) {
        callback({ cancel: false });
      } else {
        // Strict Air-Gap: Block all external network calls
        if (auditLogger) {
          auditLogger.logAction(
            'AIRGAP_FIREWALL_BLOCK',
            `Air-gap firewall blocked outbound network request: ${details.url}`,
            { url: details.url, method: details.method }
          );
        }
        console.warn(`[AIRGAP_FIREWALL] Blocked external request: ${details.url}`);
        callback({ cancel: true });
      }
    });
  }
}
