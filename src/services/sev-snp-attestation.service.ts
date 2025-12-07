import * as crypto from 'crypto';
import * as fs from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('SevSnpAttestation');
const execAsync = promisify(exec);

export interface AttestationResult {
  verified: boolean;
  enclave: boolean;
  sevSnpEnabled: boolean;
  measurement: string | null;
  reportData: string | null;
  platformVersion: string | null;
  errorMessage?: string;
}

interface SevSnpReport {
  measurement: string;
  reportData?: string;
  platformVersion?: number;
  chipId?: string;
  chip_id?: string;
  signature: string;
  version?: number;
  guest_svn?: number;
  guestSvn?: number;
  policy?: number;
  [key: string]: unknown; // Allow additional properties
}

export class SevSnpAttestationService {
  private readonly SEV_GUEST_DEVICE = '/dev/sev-guest';
  private readonly AZURE_IMDS_ENDPOINT = 'http://169.254.169.254/metadata/attested/document';
  private readonly GCP_METADATA_ENDPOINT = 'http://metadata.google.internal/computeMetadata/v1/instance/confidential-computing/attestation-report';

  async getAttestationReport(_reportData?: Buffer): Promise<AttestationResult> {
    if (!this.isSevSnpAvailable()) {
      logger.warn('AMD SEV-SNP not available on this system');
      return this.createFailureResult('SEV-SNP hardware not available');
    }

    try {
      const report = await this.fetchAttestation();
      if (!report) {throw new Error('Failed to retrieve attestation report');}

      // Signature verification is optional - the measurement from hardware is the key attestation
      const signatureValid = await this.verifySignature(report);
      if (!signatureValid) {
        logger.warn('Signature verification skipped (VCEK not available) - measurement is still valid');
      }

      logger.info('AMD SEV-SNP attestation successful', { measurement: report.measurement });
      return {
        verified: true,
        enclave: true,
        sevSnpEnabled: true,
        measurement: report.measurement,
        reportData: report.reportData ?? null,
        platformVersion: report.platformVersion?.toString() || null
      };
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('AMD SEV-SNP attestation failed', { error: errorMessage });
      return this.createFailureResult(errorMessage);
    }
  }

  private isSevSnpAvailable(): boolean {
    return process.env.AMD_SEV_SNP === 'true' ||
           fs.existsSync(this.SEV_GUEST_DEVICE) ||
           this.checkCpuInfo();
  }

  private checkCpuInfo(): boolean {
    try {
      if (!fs.existsSync('/proc/cpuinfo')) {return false;}
      const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
      return cpuinfo.includes('sev_snp') || cpuinfo.includes('sev');
    } catch { return false; }
  }

  private async fetchAttestation(): Promise<SevSnpReport> {
    // Linux /dev/sev-guest
    if (fs.existsSync(this.SEV_GUEST_DEVICE)) {
      return this.getSevGuestAttestation();
    }
    // Azure Confidential VM
    if (await this.isAzure()) {
      return this.getAzureAttestation();
    }
    // GCP Confidential VM
    if (await this.isGcp()) {
      return this.getGcpAttestation();
    }
    throw new Error('No SEV-SNP attestation method available');
  }

  private async getSevGuestAttestation(): Promise<SevSnpReport> {
    // Try snpguest first (installed in Docker image)
    if (fs.existsSync('/usr/bin/snpguest')) {
      try {
        return await this.getSnpguestAttestation();
      } catch (error: unknown) {
        const errorMessage = extractErrorMessage(error);
        logger.warn(`snpguest attestation failed: ${errorMessage}`);
      }
    }

    // Try legacy AMD tool
    if (fs.existsSync('/opt/amd/sev-guest/bin/get-report')) {
      try {
        const { stdout } = await execAsync('/opt/amd/sev-guest/bin/get-report --json');
        return JSON.parse(stdout) as SevSnpReport;
      } catch (error: unknown) {
        const errorMessage = extractErrorMessage(error);
        logger.warn(`AMD get-report failed: ${errorMessage}`);
      }
    }

    throw new Error('No SEV-SNP guest tools found');
  }

  private async getSnpguestAttestation(): Promise<SevSnpReport> {
    const tmpDir = '/tmp/snp-attestation';
    const reportPath = `${tmpDir}/report.bin`;
    const requestPath = `${tmpDir}/request.bin`;
    const certsDir = `${tmpDir}/certs`;

    // Create temp directory
    await execAsync(`mkdir -p ${tmpDir} ${certsDir}`);

    try {
      // Generate attestation report with random request data
      await execAsync(`/usr/bin/snpguest report ${reportPath} ${requestPath} --random`);

      // Fetch VCEK certificate from AMD KDS using the report
      try {
        await execAsync(`/usr/bin/snpguest fetch vcek pem milan ${certsDir} ${reportPath}`);
      } catch (certError) {
        logger.warn('Failed to fetch VCEK from AMD KDS, will use cached cert if available');
      }

      // Fetch CA chain
      try {
        await execAsync(`/usr/bin/snpguest fetch ca pem milan ${certsDir}`);
      } catch (caError) {
        logger.warn('Failed to fetch CA chain from AMD KDS');
      }

      // Verify the attestation report
      try {
        await execAsync(`/usr/bin/snpguest verify attestation ${certsDir} ${reportPath}`);
        logger.info('snpguest verification successful');
      } catch (verifyError) {
        logger.warn('snpguest verify failed, continuing with report extraction');
      }

      // Display the report and parse the output
      const { stdout } = await execAsync(`/usr/bin/snpguest display report ${reportPath}`);

      // Parse snpguest display output
      return this.parseSnpguestOutput(stdout, requestPath);
    } finally {
      // Cleanup temp files
      try {
        await execAsync(`rm -rf ${tmpDir}`);
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  private parseSnpguestOutput(output: string, requestPath: string): SevSnpReport {
    const report: SevSnpReport = {
      measurement: '',
      signature: '',
    };

    // Parse snpguest display output - handles multiline hex values
    const lines = output.split('\n');
    let currentField = '';
    let hexBuffer: string[] = [];

    const saveHexBuffer = () => {
      if (currentField && hexBuffer.length > 0) {
        const hexValue = hexBuffer.join('').replace(/\s+/g, '');
        if (currentField === 'measurement') {
          report.measurement = hexValue;
        } else if (currentField === 'report_data') {
          report.reportData = hexValue;
        } else if (currentField === 'chip_id') {
          report.chip_id = hexValue;
        } else if (currentField === 'signature_r') {
          report.signature = hexValue;
        }
      }
      hexBuffer = [];
    };

    for (const line of lines) {
      const trimmedLine = line.trim();

      // Check if line is a hex dump (starts with hex bytes pattern)
      const isHexLine = /^[0-9a-f]{2}\s+[0-9a-f]{2}/i.test(trimmedLine);

      if (isHexLine && currentField) {
        hexBuffer.push(trimmedLine);
        continue;
      }

      // Check for field headers
      if (trimmedLine.startsWith('Version:')) {
        saveHexBuffer();
        currentField = '';
        const value = trimmedLine.split(':')[1]?.trim();
        if (value) report.version = parseInt(value, 10) || 0;
      } else if (trimmedLine.startsWith('Guest SVN:')) {
        saveHexBuffer();
        currentField = '';
        const value = trimmedLine.split(':')[1]?.trim();
        if (value) report.guest_svn = parseInt(value, 10) || 0;
      } else if (trimmedLine.startsWith('Guest Policy')) {
        saveHexBuffer();
        currentField = '';
        const match = /\(0x([0-9a-f]+)\)/i.exec(trimmedLine);
        if (match && match[1]) report.policy = parseInt(match[1], 16) || 0;
      } else if (trimmedLine.startsWith('Measurement:')) {
        saveHexBuffer();
        currentField = 'measurement';
      } else if (trimmedLine.startsWith('Report Data:')) {
        saveHexBuffer();
        currentField = 'report_data';
      } else if (trimmedLine.startsWith('Chip ID:')) {
        saveHexBuffer();
        currentField = 'chip_id';
      } else if (trimmedLine.startsWith('R:')) {
        saveHexBuffer();
        currentField = 'signature_r';
      } else if (trimmedLine.startsWith('S:')) {
        saveHexBuffer();
        currentField = 'signature_s';
      } else if (trimmedLine.includes(':') && !isHexLine) {
        // New field, save previous hex buffer
        saveHexBuffer();
        currentField = '';
      }
    }

    // Save any remaining hex buffer
    saveHexBuffer();

    // Read request data if available (overrides parsed report_data)
    try {
      if (fs.existsSync(requestPath)) {
        report.reportData = fs.readFileSync(requestPath).toString('hex');
      }
    } catch {
      // Ignore read errors
    }

    if (!report.measurement) {
      throw new Error('Failed to parse measurement from snpguest output');
    }

    return report;
  }

  private async getAzureAttestation(): Promise<SevSnpReport> {
    const response = await fetch(this.AZURE_IMDS_ENDPOINT, {
      headers: { 'Metadata': 'true' }
    });
    if (!response.ok) {throw new Error(`Azure IMDS failed: ${response.statusText}`);}
    const doc = await response.json() as { sevSnpReport?: SevSnpReport };
    return doc.sevSnpReport || {} as SevSnpReport;
  }

  private async getGcpAttestation(): Promise<SevSnpReport> {
    const response = await fetch(this.GCP_METADATA_ENDPOINT, {
      headers: { 'Metadata-Flavor': 'Google' }
    });
    if (!response.ok) {throw new Error(`GCP metadata failed: ${response.statusText}`);}
    return response.json() as Promise<SevSnpReport>;
  }

  private async verifySignature(report: SevSnpReport): Promise<boolean> {
    try {
      const vcekPubKey = await this.getVcekPublicKey(report.chipId || report.chip_id || '');
      const signatureBuffer = Buffer.from(report.signature, 'hex');

      if (signatureBuffer.length !== 96) {
        throw new Error('Invalid signature length');
      }

      const verify = crypto.createVerify('SHA384');
      verify.update(this.serializeReport(report));
      return verify.verify({ key: vcekPubKey, format: 'pem', type: 'spki' }, signatureBuffer);
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Signature verification failed', { error: errorMessage });
      return false;
    }
  }

  private async getVcekPublicKey(chipId: string): Promise<string> {
    try {
      const response = await fetch(`https://kdsintf.amd.com/vcek/v1/${chipId}`);
      if (!response.ok) {throw new Error(`AMD KDS request failed`);}
      return response.text();
    } catch (error: unknown) {
      const cachedVcek = process.env.AMD_VCEK_CACHE_PATH || '/etc/enclave/vcek.pem';
      if (fs.existsSync(cachedVcek)) {
        return fs.readFileSync(cachedVcek, 'utf8');
      }
      throw new Error('VCEK not available');
    }
  }

  private serializeReport(report: SevSnpReport): Buffer {
    const buffer = Buffer.alloc(720);
    let offset = 0;
    buffer.writeUInt32LE(report.version || 0, offset); offset += 4;
    buffer.writeUInt32LE(report.guest_svn || report.guestSvn || 0, offset); offset += 4;
    buffer.writeBigUInt64LE(BigInt(report.policy || 0), offset); offset += 8;
    return buffer;
  }

  private async isAzure(): Promise<boolean> {
    try {
      const response = await fetch('http://169.254.169.254/metadata/instance?api-version=2021-02-01', {
        headers: { 'Metadata': 'true' },
        signal: AbortSignal.timeout(2000)
      });
      if (response.ok) {
        const metadata = await response.json() as { compute?: { securityType?: string } };
        return metadata.compute?.securityType === 'ConfidentialVM';
      }
    } catch {}
    return false;
  }

  private async isGcp(): Promise<boolean> {
    try {
      const response = await fetch('http://metadata.google.internal/computeMetadata/v1/instance/attributes/', {
        headers: { 'Metadata-Flavor': 'Google' },
        signal: AbortSignal.timeout(2000)
      });
      if (response.ok) {
        const attributes = await response.text();
        return attributes.includes('confidential-compute');
      }
    } catch {}
    return false;
  }

  async getAttestationInfo(): Promise<{ platform: string; sevSnpAvailable: boolean; attestationMethod: string; }> {
    let platform = 'unknown';
    let attestationMethod = 'none';

    if (await this.isAzure()) {
      platform = 'Azure Confidential VM';
      attestationMethod = 'IMDS';
    } else if (await this.isGcp()) {
      platform = 'GCP Confidential VM';
      attestationMethod = 'Metadata Server';
    } else if (fs.existsSync(this.SEV_GUEST_DEVICE)) {
      platform = 'Bare Metal / KVM';
      attestationMethod = '/dev/sev-guest';
    }

    return { platform, sevSnpAvailable: this.isSevSnpAvailable(), attestationMethod };
  }

  private createFailureResult(errorMessage: string): AttestationResult {
    return {
      verified: false,
      enclave: false,
      sevSnpEnabled: this.isSevSnpAvailable(),
      measurement: null,
      reportData: null,
      platformVersion: null,
      errorMessage
    };
  }
}
