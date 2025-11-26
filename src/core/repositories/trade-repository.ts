import { injectable, inject } from 'tsyringe';
import { PrismaClient, Trade as PrismaTrade, TradeType, TradeStatus, Prisma } from '@prisma/client';
import { Trade, CreateTradeRequest, PaginationQuery } from '../../types';

@injectable()
export class TradeRepository {
  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  /**
   * Crée un trade unique
   */
  async createTrade(tradeData: CreateTradeRequest): Promise<Trade> {
    const timestamp = tradeData.timestamp || new Date();
    const exchangeTradeId = tradeData.exchangeTradeId || `manual-${Date.now()}`;

    const createdTrade = await this.prisma.trade.create({
      data: {
        userUid: tradeData.userUid,
        symbol: tradeData.symbol,
        type: tradeData.type as TradeType,
        side: tradeData.type, // For compatibility
        quantity: tradeData.quantity,
        price: tradeData.price,
        fees: tradeData.fees,
        timestamp,
        exchange: tradeData.exchange || 'manual',
        exchangeTradeId,
        status: TradeStatus.pending,
        matchedQuantity: 0,
      },
    });

    return this.mapPrismaTradeToTrade(createdTrade);
  }

  /**
   * Crée plusieurs trades en une seule transaction
   */
  async createTrades(tradesData: CreateTradeRequest[]): Promise<Trade[]> {
    const trades = await this.prisma.$transaction(async (prisma) => {
      return Promise.all(
        tradesData.map(async (tradeData) => {
          const timestamp = tradeData.timestamp || new Date();
          const exchangeTradeId = tradeData.exchangeTradeId || `manual-${Date.now()}`;

          return prisma.trade.create({
            data: {
              userUid: tradeData.userUid,
              symbol: tradeData.symbol,
              type: tradeData.type as TradeType,
              side: tradeData.type,
              quantity: tradeData.quantity,
              price: tradeData.price,
              fees: tradeData.fees,
              timestamp,
              exchange: tradeData.exchange || 'manual',
              exchangeTradeId,
              status: TradeStatus.pending,
              matchedQuantity: 0,
            },
          });
        }),
      );
    });

    return trades.map(this.mapPrismaTradeToTrade);
  }

  /**
   * Récupère un trade par ID
   */
  async getTradeById(id: string): Promise<Trade | null> {
    const trade = await this.prisma.trade.findUnique({
      where: { id },
    });

    return trade ? this.mapPrismaTradeToTrade(trade) : null;
  }

  /**
   * Récupère tous les trades d'un utilisateur
   */
  async getTradesByUserUid(
    userUid: string,
    pagination?: PaginationQuery,
    symbol?: string,
    exchange?: string,
  ): Promise<Trade[]> {
    const page = pagination?.page || 1;
    const limit = pagination?.limit || 50;
    const sortBy = pagination?.sortBy || 'timestamp';
    const sortOrder = pagination?.sortOrder || 'desc';

    const where: Prisma.TradeWhereInput = { userUid };
    if (symbol) {
where.symbol = symbol;
}
    if (exchange) {
where.exchange = exchange;
}

    const trades = await this.prisma.trade.findMany({
      where,
      orderBy: { [sortBy]: sortOrder },
      skip: (page - 1) * limit,
      take: limit,
    });

    return trades.map(this.mapPrismaTradeToTrade);
  }

  /**
   * Récupère les trades non-matched pour un utilisateur et un symbole
   */
  async getUnmatchedTrades(userUid: string, symbol: string): Promise<Trade[]> {
    const trades = await this.prisma.trade.findMany({
      where: {
        userUid,
        symbol,
        OR: [
          { status: TradeStatus.pending },
          { status: TradeStatus.partially_matched },
        ],
      },
      orderBy: { timestamp: 'asc' }, // FIFO
    });

    return trades.map(this.mapPrismaTradeToTrade);
  }

  /**
   * Met à jour le statut d'un trade
   */
  async updateTradeStatus(id: string, status: TradeStatus, matchedQuantity?: number): Promise<void> {
    // PHASE 4: Proper type instead of any
    const updateData: Prisma.TradeUpdateInput = { status };
    if (matchedQuantity !== undefined) {
      updateData.matchedQuantity = matchedQuantity;
    }

    await this.prisma.trade.update({
      where: { id },
      data: updateData,
    });
  }

  /**
   * Supprime les trades anciens (data retention)
   */
  async deleteOldTrades(beforeDate: Date): Promise<number> {
    const result = await this.prisma.trade.deleteMany({
      where: {
        createdAt: { lt: beforeDate },
      },
    });

    return result.count;
  }

  /**
   * Compte le nombre total de trades pour un utilisateur
   */
  async countTradesByUserUid(userUid: string, symbol?: string, exchange?: string): Promise<number> {
    const where: Prisma.TradeWhereInput = { userUid };
    if (symbol) {
where.symbol = symbol;
}
    if (exchange) {
where.exchange = exchange;
}

    return this.prisma.trade.count({ where });
  }

  /**
   * Compte les trades dans une période donnée
   */
  async countTradesByDateRange(
    userUid: string,
    startDate: Date,
    endDate: Date,
    exchange?: string
  ): Promise<number> {
    const where: Prisma.TradeWhereInput = {
      userUid,
      timestamp: {
        gte: startDate,
        lte: endDate,
      }
    };
    if (exchange) {
      where.exchange = exchange;
    }

    return this.prisma.trade.count({ where });
  }

  /**
   * Récupère les trades dans une période donnée
   */
  async getTradesByDateRange(
    userUid: string,
    startDate: Date,
    endDate: Date,
    symbol?: string,
  ): Promise<Trade[]> {
    const where: Prisma.TradeWhereInput = {
      userUid,
      timestamp: {
        gte: startDate,
        lte: endDate,
      },
    };
    if (symbol) {
where.symbol = symbol;
}

    const trades = await this.prisma.trade.findMany({
      where,
      orderBy: { timestamp: 'asc' },
    });

    return trades.map(this.mapPrismaTradeToTrade);
  }

  /**
   * Récupère des statistiques de trading pour un utilisateur
   */
  async getTradeStats(userUid: string, symbol?: string): Promise<{
    totalTrades: number;
    totalVolume: number;
    totalFees: number;
    buyTrades: number;
    sellTrades: number;
  }> {
    const where: Prisma.TradeWhereInput = { userUid };
    if (symbol) {
where.symbol = symbol;
}

    const [totalTrades, stats] = await Promise.all([
      this.prisma.trade.count({ where }),
      this.prisma.trade.aggregate({
        where,
        _sum: {
          fees: true,
          quantity: true,
        },
        _count: {
          _all: true,
        },
      }),
    ]);

    const buyTrades = await this.prisma.trade.count({
      where: { ...where, type: TradeType.buy },
    });

    const sellTrades = await this.prisma.trade.count({
      where: { ...where, type: TradeType.sell },
    });

    return {
      totalTrades,
      totalVolume: stats._sum.quantity || 0,
      totalFees: stats._sum.fees || 0,
      buyTrades,
      sellTrades,
    };
  }

  /**
   * Vérifie si un trade existe déjà (pour éviter les doublons)
   */
  async tradeExists(userUid: string, exchangeTradeId: string, exchange: string): Promise<boolean> {
    const count = await this.prisma.trade.count({
      where: {
        userUid,
        exchangeTradeId,
        exchange,
      },
    });

    return count > 0;
  }

  /**
   * Récupère le timestamp du dernier trade pour un utilisateur et un exchange
   */
  async getLastTradeTimestamp(userUid: string, exchange?: string): Promise<Date | null> {
    const where: Prisma.TradeWhereInput = { userUid };
    if (exchange) {
where.exchange = exchange;
}

    const lastTrade = await this.prisma.trade.findFirst({
      where,
      orderBy: { timestamp: 'desc' },
      select: { timestamp: true },
    });

    return lastTrade?.timestamp || null;
  }

  /**
   * Récupère la plage temporelle des données de trading pour un utilisateur
   */
  async getTradeDataRange(userUid: string): Promise<{ earliest: Date; latest: Date } | null> {
    const result = await this.prisma.trade.aggregate({
      where: { userUid },
      _min: { timestamp: true },
      _max: { timestamp: true },
    });

    if (!result._min.timestamp || !result._max.timestamp) {
      return null;
    }

    return {
      earliest: result._min.timestamp,
      latest: result._max.timestamp,
    };
  }

  /**
   * Récupère les IDs de trades existants pour éviter les doublons lors de l'insertion
   */
  async getExistingTradeIds(userUid: string, exchangeTradeIds: string[]): Promise<string[]> {
    const existingTrades = await this.prisma.trade.findMany({
      where: {
        userUid,
        exchangeTradeId: { in: exchangeTradeIds },
      },
      select: { exchangeTradeId: true },
    });

    return existingTrades.map(t => t.exchangeTradeId).filter(id => id !== null);
  }

  /**
   * Crée plusieurs trades en batch avec gestion des doublons
   */
  async batchCreateTrades(tradesData: CreateTradeRequest[]): Promise<Trade[]> {
    const trades = await this.prisma.$transaction(async (prisma) => {
      return Promise.all(
        tradesData.map(async (tradeData) => {
          const timestamp = tradeData.timestamp || new Date();
          const exchangeTradeId = tradeData.exchangeTradeId || `manual-${Date.now()}`;

          return prisma.trade.create({
            data: {
              userUid: tradeData.userUid,
              symbol: tradeData.symbol,
              type: tradeData.type as TradeType,
              side: tradeData.type,
              quantity: tradeData.quantity,
              price: tradeData.price,
              fees: tradeData.fees,
              timestamp,
              exchange: tradeData.exchange || 'manual',
              exchangeTradeId,
              status: TradeStatus.pending,
              matchedQuantity: 0,
            },
          });
        }),
      );
    });

    return trades.map(this.mapPrismaTradeToTrade);
  }

  /**
   * Trouve les trades par utilisateur avec filtres pour le calcul de position
   */
  async findTradesByUser(
    userUid: string,
    filters: {
      symbols?: string[];
      startDate?: Date;
      endDate?: Date;
      exchange?: string;
    } = {},
  ): Promise<Trade[]> {
    const where: Prisma.TradeWhereInput = { userUid };

    if (filters.symbols && filters.symbols.length > 0) {
      where.symbol = { in: filters.symbols };
    }

    if (filters.startDate || filters.endDate) {
      where.timestamp = {};
      if (filters.startDate) {
where.timestamp.gte = filters.startDate;
}
      if (filters.endDate) {
where.timestamp.lte = filters.endDate;
}
    }

    if (filters.exchange) {
      where.exchange = filters.exchange;
    }

    const trades = await this.prisma.trade.findMany({
      where,
      orderBy: { timestamp: 'asc' },
    });

    return trades.map(this.mapPrismaTradeToTrade);
  }

  /**
   * Mappe un trade Prisma vers le type Trade de l'application
   */
  private mapPrismaTradeToTrade(prismaTrade: PrismaTrade): Trade {
    return {
      id: prismaTrade.id,
      userUid: prismaTrade.userUid,
      symbol: prismaTrade.symbol,
      type: prismaTrade.type as any,
      quantity: prismaTrade.quantity,
      price: prismaTrade.price,
      fees: prismaTrade.fees,
      timestamp: prismaTrade.timestamp,
      exchange: prismaTrade.exchange || undefined,
      status: prismaTrade.status as any,
      matchedQuantity: prismaTrade.matchedQuantity || undefined,
      createdAt: prismaTrade.createdAt,
      updatedAt: prismaTrade.updatedAt,
    };
  }
}