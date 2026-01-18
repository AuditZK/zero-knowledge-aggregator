import { ReportSigningService } from '../../services/report-signing.service';
import type { SignedFinancialData, DisplayParameters } from '../../types/report.types';

describe('ReportSigningService', () => {
  let service: ReportSigningService;

  const mockFinancialData: SignedFinancialData = {
    reportId: 'report-123',
    userUid: 'user_test123456789',
    generatedAt: new Date('2024-01-15T00:00:00.000Z'),
    periodStart: new Date('2024-01-01T00:00:00.000Z'),
    periodEnd: new Date('2024-01-15T00:00:00.000Z'),
    baseCurrency: 'USD',
    benchmark: 'SPY',
    dataPoints: 15,
    exchanges: ['binance', 'kraken'],
    metrics: {
      totalReturn: 12.5,
      annualizedReturn: 45.2,
      volatility: 18.3,
      sharpeRatio: 1.85,
      sortinoRatio: 2.1,
      maxDrawdown: -8.2,
      calmarRatio: 5.5,
    },
    dailyReturns: [
      {
        date: '2024-01-01',
        netReturn: 1.2,
        benchmarkReturn: 0.8,
        outperformance: 0.4,
        cumulativeReturn: 1.012,
        nav: 101200,
      },
    ],
    monthlyReturns: [
      {
        date: '2024-01',
        netReturn: 12.5,
        benchmarkReturn: 8.2,
        outperformance: 4.3,
        aum: 112500,
      },
    ],
  };

  const mockDisplayParams: DisplayParameters = {
    reportName: 'My Track Record',
    managerName: 'John Doe',
    firmName: 'Acme Trading',
    strategy: 'Long-short equity',
  };

  beforeEach(() => {
    service = new ReportSigningService();
  });

  describe('constructor', () => {
    it('should generate key pair on initialization', () => {
      const publicKey = service.getPublicKey();
      expect(publicKey).toBeDefined();
      expect(publicKey.length).toBeGreaterThan(0);
    });

    it('should generate unique key pairs for different instances', () => {
      const service1 = new ReportSigningService();
      const service2 = new ReportSigningService();

      expect(service1.getPublicKey()).not.toBe(service2.getPublicKey());
    });
  });

  describe('getPublicKey', () => {
    it('should return base64-encoded public key', () => {
      const publicKey = service.getPublicKey();

      // Base64 encoded DER format
      expect(publicKey).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });
  });

  describe('getPublicKeyFingerprint', () => {
    it('should return 16-character fingerprint', () => {
      const fingerprint = service.getPublicKeyFingerprint();

      expect(fingerprint).toMatch(/^[a-f0-9]{16}$/);
    });

    it('should return consistent fingerprint for same instance', () => {
      const fp1 = service.getPublicKeyFingerprint();
      const fp2 = service.getPublicKeyFingerprint();

      expect(fp1).toBe(fp2);
    });
  });

  describe('signFinancialData', () => {
    it('should return signed report with all required fields', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      expect(signedReport).toHaveProperty('financialData');
      expect(signedReport).toHaveProperty('displayParams');
      expect(signedReport).toHaveProperty('signature');
      expect(signedReport).toHaveProperty('publicKey');
      expect(signedReport).toHaveProperty('signatureAlgorithm');
      expect(signedReport).toHaveProperty('reportHash');
      expect(signedReport).toHaveProperty('enclaveVersion');
      expect(signedReport).toHaveProperty('enclaveMode');
    });

    it('should use ECDSA-P256-SHA256 algorithm', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      expect(signedReport.signatureAlgorithm).toBe('ECDSA-P256-SHA256');
    });

    it('should produce consistent hash for same financial data', () => {
      const report1 = service.signFinancialData(mockFinancialData, mockDisplayParams);
      const report2 = service.signFinancialData(mockFinancialData, { reportName: 'Different Name' });

      // Same financial data should produce same hash (display params not included)
      expect(report1.reportHash).toBe(report2.reportHash);
    });

    it('should produce different hash for different financial data', () => {
      const modifiedData = {
        ...mockFinancialData,
        metrics: { ...mockFinancialData.metrics, totalReturn: 15.0 },
      };

      const report1 = service.signFinancialData(mockFinancialData, mockDisplayParams);
      const report2 = service.signFinancialData(modifiedData, mockDisplayParams);

      expect(report1.reportHash).not.toBe(report2.reportHash);
    });

    it('should include public key in signed report', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      expect(signedReport.publicKey).toBe(service.getPublicKey());
    });
  });

  describe('verifySignature', () => {
    it('should verify valid signature', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      const result = service.verifySignature({
        reportHash: signedReport.reportHash,
        signature: signedReport.signature,
        publicKey: signedReport.publicKey,
      });

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should reject tampered hash', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);
      const tamperedHash = signedReport.reportHash.slice(0, -4) + '0000';

      const result = service.verifySignature({
        reportHash: tamperedHash,
        signature: signedReport.signature,
        publicKey: signedReport.publicKey,
      });

      expect(result.valid).toBe(false);
    });

    it('should reject invalid public key', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      const result = service.verifySignature({
        reportHash: signedReport.reportHash,
        signature: signedReport.signature,
        publicKey: 'invalid-base64-key',
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject signature from different key', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);
      const otherService = new ReportSigningService();

      const result = service.verifySignature({
        reportHash: signedReport.reportHash,
        signature: signedReport.signature,
        publicKey: otherService.getPublicKey(), // Different key
      });

      expect(result.valid).toBe(false);
    });
  });

  describe('verifySignedReport', () => {
    it('should verify valid signed report', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      const result = service.verifySignedReport(signedReport);

      expect(result.valid).toBe(true);
    });

    it('should detect tampered financial data', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      // Tamper with financial data
      signedReport.financialData.metrics.totalReturn = 999;

      const result = service.verifySignedReport(signedReport);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('hash mismatch');
    });

    it('should detect tampered signature', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      // Tamper with signature (flip a byte)
      const sigBytes = Buffer.from(signedReport.signature, 'base64');
      sigBytes.writeUInt8(sigBytes.readUInt8(0) ^ 0xff, 0);
      signedReport.signature = sigBytes.toString('base64');

      const result = service.verifySignedReport(signedReport);

      expect(result.valid).toBe(false);
    });

    it('should allow display params changes (not signed)', () => {
      const signedReport = service.signFinancialData(mockFinancialData, mockDisplayParams);

      // Change display params (should not affect verification)
      signedReport.displayParams.reportName = 'Changed Report Name';
      signedReport.displayParams.managerName = 'Changed Manager';

      const result = service.verifySignedReport(signedReport);

      expect(result.valid).toBe(true);
    });
  });
});
