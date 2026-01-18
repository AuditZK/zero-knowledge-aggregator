import { SevSnpAttestationService } from '../../services/sev-snp-attestation.service';
import * as fs from 'node:fs';
import { exec } from 'node:child_process';

// Mock the entire fs module
jest.mock('node:fs');
jest.mock('node:child_process');

const mockFs = fs as jest.Mocked<typeof fs>;
const mockExec = exec as jest.MockedFunction<typeof exec>;

describe('SevSnpAttestationService', () => {
  let service: SevSnpAttestationService;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    service = new SevSnpAttestationService();
    originalEnv = { ...process.env };
    jest.clearAllMocks();

    // Default: no SEV-SNP hardware available
    mockFs.existsSync.mockReturnValue(false);
    delete process.env.AMD_SEV_SNP;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('setTlsFingerprint', () => {
    it('should accept valid 32-byte fingerprint', () => {
      const fingerprint = Buffer.alloc(32, 0xab);

      expect(() => {
        service.setTlsFingerprint(fingerprint);
      }).not.toThrow();
    });

    it('should reject fingerprint that is not 32 bytes', () => {
      const shortFingerprint = Buffer.alloc(16, 0xab);

      expect(() => {
        service.setTlsFingerprint(shortFingerprint);
      }).toThrow('TLS fingerprint must be 32 bytes (SHA-256)');
    });

    it('should reject empty fingerprint', () => {
      const emptyFingerprint = Buffer.alloc(0);

      expect(() => {
        service.setTlsFingerprint(emptyFingerprint);
      }).toThrow('TLS fingerprint must be 32 bytes (SHA-256)');
    });

    it('should reject too long fingerprint', () => {
      const longFingerprint = Buffer.alloc(64, 0xab);

      expect(() => {
        service.setTlsFingerprint(longFingerprint);
      }).toThrow('TLS fingerprint must be 32 bytes (SHA-256)');
    });
  });

  describe('getAttestationReport', () => {
    it('should return failure when SEV-SNP not available', async () => {
      mockFs.existsSync.mockReturnValue(false);
      delete process.env.AMD_SEV_SNP;

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.enclave).toBe(false);
      expect(result.sevSnpEnabled).toBe(false);
      expect(result.errorMessage).toBe('SEV-SNP hardware not available');
    });

    it('should detect SEV-SNP via environment variable', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      const result = await service.getAttestationReport();

      // Will fail because no attestation method is available, but sevSnpEnabled should be true
      expect(result.sevSnpEnabled).toBe(true);
    });

    it('should detect SEV-SNP via /dev/sev-guest', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        return path === '/dev/sev-guest';
      });

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(true);
    });

    it('should detect SEV-SNP via cpuinfo', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        return path === '/proc/cpuinfo';
      });
      mockFs.readFileSync.mockReturnValue('flags: sev_snp sev');

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(true);
    });
  });

  describe('getAttestationInfo', () => {
    beforeEach(() => {
      // Mock global fetch
      global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should return unknown platform when no platform detected', async () => {
      mockFs.existsSync.mockReturnValue(false);

      const info = await service.getAttestationInfo();

      expect(info.platform).toBe('unknown');
      expect(info.attestationMethod).toBe('none');
    });

    it('should detect bare metal / KVM platform', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        return path === '/dev/sev-guest';
      });

      const info = await service.getAttestationInfo();

      expect(info.platform).toBe('Bare Metal / KVM');
      expect(info.attestationMethod).toBe('/dev/sev-guest');
    });

    it('should detect Azure Confidential VM', async () => {
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              compute: { securityType: 'ConfidentialVM' }
            })
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const info = await service.getAttestationInfo();

      expect(info.platform).toBe('Azure Confidential VM');
      expect(info.attestationMethod).toBe('IMDS');
    });

    it('should detect GCP Confidential VM', async () => {
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254')) {
          return Promise.reject(new Error('Timeout'));
        }
        if (url.includes('metadata.google.internal')) {
          return Promise.resolve({
            ok: true,
            text: () => Promise.resolve('confidential-compute=true')
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const info = await service.getAttestationInfo();

      expect(info.platform).toBe('GCP Confidential VM');
      expect(info.attestationMethod).toBe('Metadata Server');
    });

    it('should handle Azure detection failure gracefully', async () => {
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));

      const info = await service.getAttestationInfo();

      expect(info.platform).toBe('unknown');
    });

    it('should return sevSnpAvailable status', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      const info = await service.getAttestationInfo();

      expect(info.sevSnpAvailable).toBe(true);
    });
  });

  describe('cpuinfo detection', () => {
    it('should detect sev_snp flag', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        return path === '/proc/cpuinfo';
      });
      mockFs.readFileSync.mockReturnValue(
        'processor: 0\nflags: fpu vme de pse sev sev_snp\nmodel name: AMD EPYC'
      );

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(true);
    });

    it('should detect sev flag (without snp)', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        return path === '/proc/cpuinfo';
      });
      mockFs.readFileSync.mockReturnValue(
        'processor: 0\nflags: fpu vme de pse sev\nmodel name: AMD EPYC'
      );

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(true);
    });

    it('should return false when cpuinfo has no sev flags', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        return path === '/proc/cpuinfo';
      });
      mockFs.readFileSync.mockReturnValue(
        'processor: 0\nflags: fpu vme de pse\nmodel name: Intel Core'
      );

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(false);
    });

    it('should handle cpuinfo read error', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        return path === '/proc/cpuinfo';
      });
      mockFs.readFileSync.mockImplementation(() => {
        throw new Error('Permission denied');
      });

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(false);
    });
  });

  describe('failure result creation', () => {
    it('should include error message in failure result', async () => {
      mockFs.existsSync.mockReturnValue(false);

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.enclave).toBe(false);
      expect(result.measurement).toBeNull();
      expect(result.reportData).toBeNull();
      expect(result.platformVersion).toBeNull();
      expect(result.vcekVerified).toBe(false);
      expect(result.errorMessage).toBeDefined();
    });
  });

  describe('attestation result structure', () => {
    it('should have all required fields in failure result', async () => {
      mockFs.existsSync.mockReturnValue(false);

      const result = await service.getAttestationReport();

      expect(result).toHaveProperty('verified');
      expect(result).toHaveProperty('enclave');
      expect(result).toHaveProperty('sevSnpEnabled');
      expect(result).toHaveProperty('measurement');
      expect(result).toHaveProperty('reportData');
      expect(result).toHaveProperty('platformVersion');
      expect(result).toHaveProperty('vcekVerified');
    });
  });

  describe('Azure attestation', () => {
    beforeEach(() => {
      process.env.AMD_SEV_SNP = 'true';
    });

    it('should fetch attestation from Azure IMDS', async () => {
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254/metadata/instance')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ compute: { securityType: 'ConfidentialVM' } })
          });
        }
        if (url.includes('169.254.169.254/metadata/attested/document')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              sevSnpReport: {
                measurement: 'azure_measurement_123',
                signature: 'azure_sig',
                platformVersion: 1,
                vcekVerified: true
              }
            })
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(true);
      expect(result.enclave).toBe(true);
      expect(result.measurement).toBe('azure_measurement_123');
    });

    it('should handle Azure IMDS attestation failure', async () => {
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254/metadata/instance')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ compute: { securityType: 'ConfidentialVM' } })
          });
        }
        if (url.includes('169.254.169.254/metadata/attested/document')) {
          return Promise.resolve({
            ok: false,
            statusText: 'Service Unavailable'
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.errorMessage).toContain('Azure IMDS failed');
    });

    it('should handle empty sevSnpReport from Azure', async () => {
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254/metadata/instance')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ compute: { securityType: 'ConfidentialVM' } })
          });
        }
        if (url.includes('169.254.169.254/metadata/attested/document')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({}) // No sevSnpReport
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      // Should return failure when measurement is missing
      expect(result.verified).toBe(false);
    });
  });

  describe('GCP attestation', () => {
    beforeEach(() => {
      process.env.AMD_SEV_SNP = 'true';
    });

    it('should fetch attestation from GCP metadata', async () => {
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254')) {
          return Promise.reject(new Error('Not Azure'));
        }
        if (url.includes('metadata.google.internal/computeMetadata/v1/instance/attributes')) {
          return Promise.resolve({
            ok: true,
            text: () => Promise.resolve('confidential-compute=true')
          });
        }
        if (url.includes('metadata.google.internal/computeMetadata/v1/instance/confidential-computing/attestation-report')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              measurement: 'gcp_measurement_456',
              signature: 'gcp_sig',
              vcekVerified: true
            })
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(true);
      expect(result.enclave).toBe(true);
      expect(result.measurement).toBe('gcp_measurement_456');
    });

    it('should handle GCP metadata attestation failure', async () => {
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254')) {
          return Promise.reject(new Error('Not Azure'));
        }
        if (url.includes('metadata.google.internal/computeMetadata/v1/instance/attributes')) {
          return Promise.resolve({
            ok: true,
            text: () => Promise.resolve('confidential-compute=true')
          });
        }
        if (url.includes('confidential-computing/attestation-report')) {
          return Promise.resolve({
            ok: false,
            statusText: 'Not Found'
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.errorMessage).toContain('GCP metadata failed');
    });
  });

  describe('TLS fingerprint binding', () => {
    it('should include TLS fingerprint in attestation report data', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      // Set TLS fingerprint
      const fingerprint = Buffer.alloc(32, 0xab);
      service.setTlsFingerprint(fingerprint);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254/metadata/instance')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ compute: { securityType: 'ConfidentialVM' } })
          });
        }
        if (url.includes('169.254.169.254/metadata/attested/document')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              sevSnpReport: {
                measurement: 'measurement_with_tls',
                signature: 'sig',
                reportData: 'abababababababababababababababababababababababababababababababab00000000000000000000000000000000',
                vcekVerified: true
              }
            })
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      // reportData should be truncated to first 64 hex chars (32 bytes)
      expect(result.reportData).toBe('abababababababababababababababababababababababababababababababab');
    });
  });

  describe('no attestation method available', () => {
    it('should return error when no method is available', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.errorMessage).toBe('No SEV-SNP attestation method available');
    });
  });

  describe('/dev/sev-guest detection', () => {
    it('should return error when no guest tools found', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        // snpguest and legacy tool not available
        return false;
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.errorMessage).toContain('No SEV-SNP guest tools found');
    });
  });

  describe('snpguest attestation', () => {
    const mockSnpguestOutput = `
Version: 2
Guest SVN: 0
Guest Policy: 0x30000 (ABI_MAJOR: 0, ABI_MINOR: 0, SMT: 1, MIGRATE_MA: 0, DEBUG: 0, SINGLE_SOCKET: 0)

Measurement:
  ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89
  ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89
  ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89

Report Data:
  11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00
  11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00
  11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00
  11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00

Chip ID:
  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99
  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99
  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99
  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99

Signature:
R:
  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
S:
  11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20
  11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20
`;

    const createExecMock = (handlers: Record<string, { stdout: string; stderr: string } | Error>) => {
      return jest.fn().mockImplementation((cmd: string, callback?: (error: Error | null, result: { stdout: string; stderr: string }) => void) => {
        for (const [pattern, response] of Object.entries(handlers)) {
          if (cmd.includes(pattern)) {
            if (callback) {
              if (response instanceof Error) {
                callback(response, { stdout: '', stderr: '' });
              } else {
                callback(null, response);
              }
            }
            return;
          }
        }
        // Default success
        if (callback) {
          callback(null, { stdout: '', stderr: '' });
        }
      });
    };

    it('should use snpguest when available', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/usr/bin/snpguest') return true;
        return false;
      });
      mockFs.writeFileSync.mockImplementation(() => {});
      mockFs.readFileSync.mockReturnValue(Buffer.alloc(64, 0x11));

      (exec as unknown as jest.Mock).mockImplementation(createExecMock({
        'snpguest display report': { stdout: mockSnpguestOutput, stderr: '' },
        'snpguest verify attestation': { stdout: 'OK', stderr: '' }
      }));

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(true);
      expect(result.enclave).toBe(true);
    });

    it('should use snpguest with TLS fingerprint binding', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/usr/bin/snpguest') return true;
        if (path === '/tmp/snp-attestation/request.bin') return true;
        return false;
      });
      mockFs.writeFileSync.mockImplementation(() => {});
      mockFs.readFileSync.mockReturnValue(Buffer.alloc(64, 0xab));

      (exec as unknown as jest.Mock).mockImplementation(createExecMock({
        'snpguest display report': { stdout: mockSnpguestOutput, stderr: '' },
        'snpguest verify attestation': { stdout: 'OK', stderr: '' }
      }));

      // Set TLS fingerprint
      const fingerprint = Buffer.alloc(32, 0xab);
      service.setTlsFingerprint(fingerprint);

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(true);
      expect(mockFs.writeFileSync).toHaveBeenCalled();
    });

    it('should fall back to legacy AMD tool when snpguest fails', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/usr/bin/snpguest') return true;
        if (path === '/opt/amd/sev-guest/bin/get-report') return true;
        return false;
      });

      (exec as unknown as jest.Mock).mockImplementation(createExecMock({
        'snpguest': new Error('snpguest failed'),
        'get-report': { stdout: JSON.stringify({ measurement: 'legacy_measurement', signature: 'sig' }), stderr: '' }
      }));

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(true);
    });

    it('should handle VCEK fetch failure gracefully', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/usr/bin/snpguest') return true;
        return false;
      });
      mockFs.writeFileSync.mockImplementation(() => {});
      mockFs.readFileSync.mockReturnValue(Buffer.alloc(64, 0x11));

      (exec as unknown as jest.Mock).mockImplementation(createExecMock({
        'fetch vcek': new Error('VCEK fetch failed'),
        'fetch ca': new Error('CA fetch failed'),
        'snpguest display report': { stdout: mockSnpguestOutput, stderr: '' },
        'snpguest verify': new Error('Verify failed')
      }));

      const result = await service.getAttestationReport();

      // Should still work but vcekVerified should be false
      expect(result.sevSnpEnabled).toBe(true);
      expect(result.vcekVerified).toBe(false);
    });

    it('should parse snpguest output with missing fields', async () => {
      const minimalOutput = `
Version: 1
Measurement:
  ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89
  ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89
  ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89
`;

      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/usr/bin/snpguest') return true;
        return false;
      });
      mockFs.writeFileSync.mockImplementation(() => {});
      mockFs.readFileSync.mockImplementation(() => {
        throw new Error('File not found');
      });

      (exec as unknown as jest.Mock).mockImplementation(createExecMock({
        'snpguest display report': { stdout: minimalOutput, stderr: '' },
        'snpguest verify': { stdout: 'OK', stderr: '' }
      }));

      const result = await service.getAttestationReport();

      expect(result.sevSnpEnabled).toBe(true);
      expect(result.measurement).toBeTruthy();
    });

    it('should handle cleanup errors gracefully', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/usr/bin/snpguest') return true;
        return false;
      });
      mockFs.writeFileSync.mockImplementation(() => {});
      mockFs.readFileSync.mockReturnValue(Buffer.alloc(64, 0x11));

      (exec as unknown as jest.Mock).mockImplementation(createExecMock({
        'rm -rf': new Error('Cleanup failed'),
        'snpguest display report': { stdout: mockSnpguestOutput, stderr: '' },
        'snpguest verify': { stdout: 'OK', stderr: '' }
      }));

      const result = await service.getAttestationReport();

      // Should succeed despite cleanup error
      expect(result.sevSnpEnabled).toBe(true);
    });

    it('should fail gracefully when measurement parsing fails', async () => {
      const invalidOutput = `
Version: 1
Some random text without measurement
`;

      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/usr/bin/snpguest') return true;
        return false;
      });
      mockFs.writeFileSync.mockImplementation(() => {});
      mockFs.readFileSync.mockImplementation(() => {
        throw new Error('File not found');
      });

      (exec as unknown as jest.Mock).mockImplementation(createExecMock({
        'snpguest display report': { stdout: invalidOutput, stderr: '' }
      }));

      const result = await service.getAttestationReport();

      // When parsing fails, snpguest is caught and falls through to legacy tool
      // which doesn't exist, so the final error is "No SEV-SNP guest tools found"
      expect(result.verified).toBe(false);
      expect(result.errorMessage).toBeDefined();
    });
  });

  describe('legacy AMD tool attestation', () => {
    it('should use legacy AMD tool when snpguest is not available', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/opt/amd/sev-guest/bin/get-report') return true;
        return false;
      });

      (exec as unknown as jest.Mock).mockImplementation((cmd: string, callback?: (error: Error | null, result: { stdout: string; stderr: string }) => void) => {
        if (callback) {
          if (cmd.includes('get-report')) {
            callback(null, {
              stdout: JSON.stringify({
                measurement: 'legacy_measurement_abc',
                signature: 'legacy_signature',
                platformVersion: 2
              }),
              stderr: ''
            });
          } else {
            callback(null, { stdout: '', stderr: '' });
          }
        }
      });

      const result = await service.getAttestationReport();

      expect(result.measurement).toBe('legacy_measurement_abc');
    });

    it('should handle legacy AMD tool failure', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        if (path === '/dev/sev-guest') return true;
        if (path === '/opt/amd/sev-guest/bin/get-report') return true;
        return false;
      });

      (exec as unknown as jest.Mock).mockImplementation((cmd: string, callback?: (error: Error | null, result: { stdout: string; stderr: string }) => void) => {
        if (callback) {
          callback(new Error('Tool execution failed'), { stdout: '', stderr: '' });
        }
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.errorMessage).toContain('No SEV-SNP guest tools found');
    });
  });

  describe('attestation report with vcek verification', () => {
    it('should set verified=true when vcekVerified is true', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254/metadata/instance')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ compute: { securityType: 'ConfidentialVM' } })
          });
        }
        if (url.includes('169.254.169.254/metadata/attested/document')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              sevSnpReport: {
                measurement: 'verified_measurement',
                signature: 'sig',
                vcekVerified: true,
                platformVersion: 3
              }
            })
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(true);
      expect(result.vcekVerified).toBe(true);
      expect(result.platformVersion).toBe('3');
    });

    it('should set verified=false when vcekVerified is false', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254/metadata/instance')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ compute: { securityType: 'ConfidentialVM' } })
          });
        }
        if (url.includes('169.254.169.254/metadata/attested/document')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              sevSnpReport: {
                measurement: 'unverified_measurement',
                signature: 'sig',
                vcekVerified: false
              }
            })
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.vcekVerified).toBe(false);
      expect(result.enclave).toBe(true);
    });
  });

  describe('reportData handling', () => {
    it('should return full reportData when no TLS fingerprint set', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254/metadata/instance')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ compute: { securityType: 'ConfidentialVM' } })
          });
        }
        if (url.includes('169.254.169.254/metadata/attested/document')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              sevSnpReport: {
                measurement: 'test_measurement',
                signature: 'sig',
                reportData: 'aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                vcekVerified: true
              }
            })
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      // Without TLS fingerprint, reportData should be returned as-is (full length)
      expect(result.reportData).toBe('aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
    });

    it('should return null reportData when not present', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254/metadata/instance')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ compute: { securityType: 'ConfidentialVM' } })
          });
        }
        if (url.includes('169.254.169.254/metadata/attested/document')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
              sevSnpReport: {
                measurement: 'test_measurement',
                signature: 'sig',
                vcekVerified: true
                // No reportData
              }
            })
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      expect(result.reportData).toBeNull();
    });
  });

  describe('GCP attestation response handling', () => {
    it('should handle GCP response without ok check', async () => {
      process.env.AMD_SEV_SNP = 'true';
      mockFs.existsSync.mockReturnValue(false);

      global.fetch = jest.fn().mockImplementation((url: string) => {
        if (url.includes('169.254.169.254')) {
          return Promise.reject(new Error('Not Azure'));
        }
        if (url.includes('metadata.google.internal/computeMetadata/v1/instance/attributes')) {
          return Promise.resolve({
            ok: false,
            text: () => Promise.resolve('')
          });
        }
        return Promise.reject(new Error('Not found'));
      });

      const result = await service.getAttestationReport();

      expect(result.verified).toBe(false);
      expect(result.errorMessage).toBe('No SEV-SNP attestation method available');
    });
  });
});
