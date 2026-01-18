import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
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
  vcekVerified: boolean;
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
  vcekVerified?: boolean; // True if snpguest verify attestation succeeded
  [key: string]: unknown; // Allow additional properties
}

export class SevSnpAttestationService {
  private readonly SEV_GUEST_DEVICE = '/dev/sev-guest';
  // NOSONAR: Azure IMDS only supports HTTP - link-local address (169.254.x.x) is VM-internal only
  private readonly AZURE_IMDS_ENDPOINT = 'http://169.254.169.254/metadata/attested/document'; // NOSONAR
  // NOSONAR: GCP Metadata Server only supports HTTP - internal DNS is VM-internal only
  private readonly GCP_METADATA_ENDPOINT = 'http://metadata.google.internal/computeMetadata/v1/instance/confidential-computing/attestation-report'; // NOSONAR

  private tlsFingerprint: Buffer | null = null;

  /** Binds TLS fingerprint to attestation reportData field. */
  setTlsFingerprint(fingerprint: Buffer): void {
    if (fingerprint.length !== 32) {
      throw new Error('TLS fingerprint must be 32 bytes (SHA-256)');
    }
    this.tlsFingerprint = fingerprint;
    logger.info('TLS fingerprint bound to attestation service', {
      fingerprintHex: fingerprint.toString('hex').slice(0, 16) + '...'
    });
  }

  async getAttestationReport(): Promise<AttestationResult> {
    if (!this.isSevSnpAvailable()) {
      logger.warn('AMD SEV-SNP not available on this system');
      return this.createFailureResult('SEV-SNP hardware not available');
    }

    try {
      const report = await this.fetchAttestation();
      if (!report) {throw new Error('Failed to retrieve attestation report');}

      // vcekVerified is set by snpguest verify attestation command
      const vcekVerified = report.vcekVerified === true;

      if (vcekVerified) {
        logger.info('AMD SEV-SNP attestation VERIFIED with VCEK certificate chain', {
          measurement: report.measurement
        });
      } else {
        logger.warn('AMD SEV-SNP attestation completed but VCEK verification failed - measurement is from hardware but not cryptographically verified');
      }

      // reportData now contains TLS fingerprint (if set) - it's SIGNED by AMD
      // Extract first 32 bytes (SHA-256 fingerprint) from 64-byte reportData
      let reportDataHex = report.reportData ?? null;
      if (reportDataHex && this.tlsFingerprint) {
        // Return only the fingerprint part (first 64 hex chars = 32 bytes)
        reportDataHex = reportDataHex.slice(0, 64);
      }

      return {
        verified: vcekVerified, // Only true if VCEK verification succeeded
        enclave: true,
        sevSnpEnabled: true,
        measurement: report.measurement,
        reportData: reportDataHex,
        platformVersion: report.platformVersion?.toString() || null,
        vcekVerified
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
    // SECURITY: Use mkdtempSync to create unique directory with unpredictable name
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'snp-attestation-'));
    const reportPath = path.join(tmpDir, 'report.bin');
    const requestPath = path.join(tmpDir, 'request.bin');
    const certsDir = path.join(tmpDir, 'certs');

    // Create certs subdirectory
    fs.mkdirSync(certsDir, { mode: 0o700 });

    try {
      // Generate attestation report with TLS fingerprint as request data (for TLS binding)
      // If TLS fingerprint is set, use it; otherwise use random data
      if (this.tlsFingerprint) {
        // Write TLS fingerprint (32 bytes) padded to 64 bytes as request data
        const paddedFingerprint = Buffer.alloc(64, 0);
        this.tlsFingerprint.copy(paddedFingerprint, 0);
        fs.writeFileSync(requestPath, paddedFingerprint);
        await execAsync(`/usr/bin/snpguest report ${reportPath} ${requestPath}`);
        logger.info('Generated attestation with TLS fingerprint binding');
      } else {
        await execAsync(`/usr/bin/snpguest report ${reportPath} ${requestPath} --random`);
        logger.warn('Generated attestation with random data (no TLS binding)');
      }

      // Fetch VCEK certificate from AMD KDS using the report
      // snpguest 0.6.0 syntax: fetch vcek <encoding> <processor_model> <certs_dir> <att_report_path>
      try {
        await execAsync(`/usr/bin/snpguest fetch vcek pem milan ${certsDir} ${reportPath}`);
        logger.info('Successfully fetched VCEK certificate from AMD KDS');
      } catch (certError: unknown) {
        logger.warn('Failed to fetch VCEK from AMD KDS, will use cached cert if available', {
          error: extractErrorMessage(certError)
        });
      }

      // Fetch CA chain from AMD KDS
      // snpguest 0.6.0 syntax: fetch ca <encoding> <processor_model> <certs_dir> --endorser <vcek|vlek>
      try {
        await execAsync(`/usr/bin/snpguest fetch ca pem milan ${certsDir} --endorser vcek`);
        logger.info('Successfully fetched CA chain from AMD KDS');
      } catch (caError) {
        logger.warn('Failed to fetch CA chain from AMD KDS');
      }

      // Verify the attestation report using VCEK certificate chain
      let vcekVerified = false;
      try {
        await execAsync(`/usr/bin/snpguest verify attestation ${certsDir} ${reportPath}`);
        logger.info('snpguest VCEK verification successful - attestation cryptographically verified');
        vcekVerified = true;
      } catch (verifyError) {
        logger.warn('snpguest verify failed - attestation NOT cryptographically verified');
      }

      // Display the report and parse the output
      const { stdout } = await execAsync(`/usr/bin/snpguest display report ${reportPath}`);

      // Parse snpguest display output
      const report = this.parseSnpguestOutput(stdout, requestPath);
      report.vcekVerified = vcekVerified;
      return report;
    } finally {
      // Cleanup temp files
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  private parseSnpguestOutput(output: string, requestPath: string): SevSnpReport {
    const report: SevSnpReport = { measurement: '', signature: '' };
    const lines = output.split('\n');
    let currentField = '';
    let hexBuffer: string[] = [];

    for (const line of lines) {
      const trimmedLine = line.trim();
      const isHexLine = /^[0-9a-f]{2}\s+[0-9a-f]{2}/i.test(trimmedLine);

      if (isHexLine && currentField) {
        hexBuffer.push(trimmedLine);
        continue;
      }

      hexBuffer = this.saveHexBufferToReport(currentField, hexBuffer, report);
      currentField = this.parseFieldHeader(trimmedLine, report, isHexLine);
    }

    this.saveHexBufferToReport(currentField, hexBuffer, report);
    this.readRequestDataFile(requestPath, report);

    if (!report.measurement) {
      throw new Error('Failed to parse measurement from snpguest output');
    }

    return report;
  }

  private saveHexBufferToReport(
    currentField: string,
    hexBuffer: string[],
    report: SevSnpReport
  ): string[] {
    if (!currentField || hexBuffer.length === 0) return [];

    const hexValue = hexBuffer.join('').replaceAll(/\s+/g, '');
    const fieldMapping: Record<string, keyof SevSnpReport> = {
      'measurement': 'measurement',
      'report_data': 'reportData',
      'chip_id': 'chip_id',
      'signature_r': 'signature'
    };

    const reportKey = fieldMapping[currentField];
    if (reportKey) {
      (report as Record<string, unknown>)[reportKey] = hexValue;
    }

    return [];
  }

  private parseFieldHeader(line: string, report: SevSnpReport, isHexLine: boolean): string {
    const fieldParsers: Array<{ prefix: string; handler: () => string }> = [
      { prefix: 'Version:', handler: () => { this.parseIntField(line, report, 'version'); return ''; } },
      { prefix: 'Guest SVN:', handler: () => { this.parseIntField(line, report, 'guest_svn'); return ''; } },
      { prefix: 'Guest Policy', handler: () => { this.parsePolicyField(line, report); return ''; } },
      { prefix: 'Measurement:', handler: () => 'measurement' },
      { prefix: 'Report Data:', handler: () => 'report_data' },
      { prefix: 'Chip ID:', handler: () => 'chip_id' },
      { prefix: 'R:', handler: () => 'signature_r' },
      { prefix: 'S:', handler: () => 'signature_s' }
    ];

    for (const parser of fieldParsers) {
      if (line.startsWith(parser.prefix)) {
        return parser.handler();
      }
    }

    // New field with colon, reset current field
    if (line.includes(':') && !isHexLine) {
      return '';
    }

    return '';
  }

  private parseIntField(line: string, report: SevSnpReport, field: 'version' | 'guest_svn'): void {
    const value = line.split(':')[1]?.trim();
    if (value) {
      report[field] = Number.parseInt(value, 10) || 0;
    }
  }

  private parsePolicyField(line: string, report: SevSnpReport): void {
    const match = /\(0x([0-9a-f]+)\)/i.exec(line);
    if (match?.[1]) {
      report.policy = Number.parseInt(match[1], 16) || 0;
    }
  }

  private readRequestDataFile(requestPath: string, report: SevSnpReport): void {
    try {
      if (fs.existsSync(requestPath)) {
        report.reportData = fs.readFileSync(requestPath).toString('hex');
      }
    } catch {
      // Ignore read errors
    }
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

  private async isAzure(): Promise<boolean> {
    try {
      // NOSONAR: Azure IMDS only supports HTTP - link-local address is VM-internal only
      const response = await fetch('http://169.254.169.254/metadata/instance?api-version=2021-02-01', { // NOSONAR
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
      // NOSONAR: GCP Metadata Server only supports HTTP - internal DNS is VM-internal only
      const response = await fetch('http://metadata.google.internal/computeMetadata/v1/instance/attributes/', { // NOSONAR
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
      vcekVerified: false,
      errorMessage
    };
  }
}
