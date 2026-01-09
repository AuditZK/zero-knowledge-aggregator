import { injectable, inject } from 'tsyringe';
import { PrismaClient, SignedReport as PrismaSignedReport, Prisma } from '@prisma/client';
import { getLogger } from '../../utils/secure-enclave-logger';

const logger = getLogger('SignedReportRepository');

export interface SignedReportData {
  id: string;
  reportId: string;
  userUid: string;
  startDate: Date;
  endDate: Date;
  benchmark: string | null;
  reportData: Record<string, unknown>;
  signature: string;
  reportHash: string;
  enclaveVersion: string;
  createdAt: Date;
}

@injectable()
export class SignedReportRepository {
  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  /**
   * Find existing report by period and benchmark
   * Returns cached report if same period was already generated
   */
  async findByPeriod(
    userUid: string,
    startDate: Date,
    endDate: Date,
    benchmark: string | null
  ): Promise<SignedReportData | null> {
    logger.debug('Looking for existing report', {
      userUid,
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      benchmark
    });

    const report = await this.prisma.signedReport.findUnique({
      where: {
        userUid_startDate_endDate_benchmark: {
          userUid,
          startDate,
          endDate,
          benchmark: benchmark || ''
        }
      }
    });

    if (report) {
      logger.info('Found existing report for period', {
        reportId: report.reportId,
        createdAt: report.createdAt.toISOString()
      });
      return this.mapToSignedReportData(report);
    }

    return null;
  }

  /**
   * Save a new signed report
   */
  async save(data: Omit<SignedReportData, 'id' | 'createdAt'>): Promise<SignedReportData> {
    logger.info('Saving new signed report', {
      reportId: data.reportId,
      userUid: data.userUid,
      period: `${data.startDate.toISOString()} - ${data.endDate.toISOString()}`
    });

    const report = await this.prisma.signedReport.create({
      data: {
        reportId: data.reportId,
        userUid: data.userUid,
        startDate: data.startDate,
        endDate: data.endDate,
        benchmark: data.benchmark || '',
        reportData: data.reportData as Prisma.InputJsonValue,
        signature: data.signature,
        reportHash: data.reportHash,
        enclaveVersion: data.enclaveVersion
      }
    });

    return this.mapToSignedReportData(report);
  }

  /**
   * Find report by reportId
   */
  async findByReportId(reportId: string): Promise<SignedReportData | null> {
    const report = await this.prisma.signedReport.findUnique({
      where: { reportId }
    });

    return report ? this.mapToSignedReportData(report) : null;
  }

  /**
   * List all reports for a user
   */
  async listByUser(userUid: string): Promise<SignedReportData[]> {
    const reports = await this.prisma.signedReport.findMany({
      where: { userUid },
      orderBy: { createdAt: 'desc' }
    });

    return reports.map(r => this.mapToSignedReportData(r));
  }

  private mapToSignedReportData(report: PrismaSignedReport): SignedReportData {
    return {
      id: report.id,
      reportId: report.reportId,
      userUid: report.userUid,
      startDate: report.startDate,
      endDate: report.endDate,
      benchmark: report.benchmark || null,
      reportData: report.reportData as Record<string, unknown>,
      signature: report.signature,
      reportHash: report.reportHash,
      enclaveVersion: report.enclaveVersion,
      createdAt: report.createdAt
    };
  }
}
