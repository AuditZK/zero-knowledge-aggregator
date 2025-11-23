import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { getLogger } from '../../utils/logger.service';

const logger = getLogger('TradeRetentionService');

/**
 * Service de gestion de la rétention des trades
 * Supprime automatiquement les trades de plus de 365 jours
 * Les returns horaires sont conservés indéfiniment car ils sont agrégés
 */
@injectable()
export class TradeRetentionService {
  private readonly RETENTION_DAYS = 365;

  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  /**
   * Nettoie les trades de plus de 365 jours
   * @returns Nombre de trades supprimés
   */
  async cleanupOldTrades(): Promise<number> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_DAYS);

      const result = await this.prisma.trade.deleteMany({
        where: {
          timestamp: {
            lt: cutoffDate,
          },
        },
      });

      const deletedCount = result.count;
      if (deletedCount > 0) {

      }

      return deletedCount;
    } catch (error) {
      logger.error('Error cleaning up old trades:', error);
      throw error;
    }
  }

  /**
   * Vérifie l'état de la rétention
   * @returns Statistiques de rétention
   */
  async getRetentionStats(): Promise<{
    totalTrades: number;
    oldTradesCount: number;
    oldestTradeDate: Date | null;
  }> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_DAYS);

      const totalTrades = await this.prisma.trade.count();

      const oldTradesCount = await this.prisma.trade.count({
        where: {
          timestamp: {
            lt: cutoffDate,
          },
        },
      });

      const oldestTrade = await this.prisma.trade.findFirst({
        orderBy: {
          timestamp: 'asc',
        },
        select: {
          timestamp: true,
        },
      });

      return {
        totalTrades,
        oldTradesCount,
        oldestTradeDate: oldestTrade?.timestamp || null,
      };
    } catch (error) {
      logger.error('Error getting retention stats:', error);
      throw error;
    }
  }

  /**
   * Programme le nettoyage automatique
   * Exécute le nettoyage toutes les 24 heures
   */
  startAutomaticCleanup(): void {
    // Nettoyage initial
    this.cleanupOldTrades().catch(error => logger.error('Error in cleanup task', error));

    // Nettoyage quotidien à 2h du matin
    const intervalMs = 24 * 60 * 60 * 1000; // 24 heures

    setInterval(async () => {
      try {
        await this.cleanupOldTrades();
      } catch (error) {
        logger.error('Scheduled trade cleanup failed:', error);
      }
    }, intervalMs);

  }
}
