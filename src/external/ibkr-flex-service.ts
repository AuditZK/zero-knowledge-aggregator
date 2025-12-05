import { injectable } from 'tsyringe';
import axios from 'axios';
import { parseStringPromise } from 'xml2js';
import { getLogger, extractErrorMessage } from '../utils/secure-enclave-logger';

const logger = getLogger('IbkrFlexService');

export interface FlexQueryConfig {
  token: string;
  queryId: string;
}

export interface FlexTrade {
  symbol: string;
  tradeID: string;
  ibOrderID: string;
  tradeDate: string;
  tradeTime: string;
  buySell: 'BUY' | 'SELL';
  quantity: number;
  tradePrice: number;
  ibCommission: number;
  ibCommissionCurrency: string;
  netCash: number;
  closePrice: number;
  fifoPnlRealized: number;
  assetCategory: string; // STK, OPT, FUT, CASH, etc.
}

export interface FlexPosition {
  symbol: string;
  position: number;
  markPrice: number;
  positionValue: number;
  openPrice: number;
  costBasisPrice: number;
  fifoPnlUnrealized: number;
}

export interface FlexCashTransaction {
  symbol: string;
  date: string;
  type: string; // Deposits, Withdrawals, Dividends, etc.
  amount: number;
  currency: string;
  description: string;
}

export interface FlexAccountSummary {
  date: string;
  cash: number;
  stockValue: number;
  optionValue: number;
  commodityValue: number;
  netLiquidationValue: number;
  unrealizedPnL: number;
  realizedPnL: number;
}

interface FlexCache {
  xmlData: string;
  timestamp: number;
}

@injectable()
export class IbkrFlexService {
  private readonly baseUrl = 'https://ndcdyn.interactivebrokers.com/Universal/servlet';
  private readonly flexCache = new Map<string, FlexCache>();
  // IBKR Flex data is daily snapshots, not real-time - cache for 30 minutes
  // This prevents rate limiting (Error 1018) during sync operations
  private readonly CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

  async requestFlexReport(token: string, queryId: string): Promise<string> {
    const startTime = Date.now();
    try {
      logger.info('Requesting Flex report', { queryId });
      const response = await axios.get(`${this.baseUrl}/FlexStatementService.SendRequest`, {
        params: { t: token, q: queryId, v: '3' },
        timeout: 30000,
      });

      const parsed = await parseStringPromise(response.data);
      if (parsed.FlexStatementResponse?.Status?.[0] === 'Fail') {
        const errorCode = parsed.FlexStatementResponse?.ErrorCode?.[0];
        const errorMessage = parsed.FlexStatementResponse?.ErrorMessage?.[0];
        throw new Error(`Flex API Error ${errorCode}: ${errorMessage}`);
      }

      const referenceCode = parsed.FlexStatementResponse?.ReferenceCode?.[0];
      if (!referenceCode) {throw new Error('No reference code received from Flex API');}

      const duration = ((Date.now() - startTime) / 1000).toFixed(3);
      logger.info(`Flex report requested successfully (${duration}s)`, { referenceCode });
      return referenceCode;
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to request Flex report', error);
      throw new Error(`Flex request failed: ${errorMessage}`);
    }
  }

  async getFlexStatement(token: string, referenceCode: string): Promise<string> {
    const startTime = Date.now();
    try {
      logger.info('Retrieving Flex statement', { referenceCode });
      const maxRetries = 20;
      const retryDelay = 3000;

      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        const response = await axios.get(`${this.baseUrl}/FlexStatementService.GetStatement`, {
          params: { t: token, q: referenceCode, v: '3' },
          timeout: 30000,
        });

        const xmlData = response.data;
        if (xmlData.includes('<FlexQueryResponse')) {
          const duration = ((Date.now() - startTime) / 1000).toFixed(3);
          logger.info(`Flex statement retrieved successfully after ${attempt} attempts (${duration}s)`);
          return xmlData;
        }

        const parsed = await parseStringPromise(xmlData);
        const status = parsed.FlexStatementResponse?.Status?.[0];

        if (status === 'Success') {
          const duration = ((Date.now() - startTime) / 1000).toFixed(3);
          logger.info(`Flex statement retrieved successfully after ${attempt} attempts (${duration}s)`);
          return xmlData;
        } else if (status === 'Fail') {
          const errorCode = parsed.FlexStatementResponse?.ErrorCode?.[0];
          const errorMessage = parsed.FlexStatementResponse?.ErrorMessage?.[0];

          if (errorCode === '1019' && attempt < maxRetries) {
            logger.info(`Statement not ready, retrying in ${retryDelay}ms (attempt ${attempt}/${maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, retryDelay));
            continue;
          }

          throw new Error(`Flex API Error ${errorCode}: ${errorMessage}`);
        }
      }

      throw new Error('Flex statement generation timeout - report not ready after retries');
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to get Flex statement', error);
      throw new Error(`Flex retrieval failed: ${errorMessage}`);
    }
  }

  async parseTrades(xmlData: string): Promise<FlexTrade[]> {
    try {
      const parsed = await parseStringPromise(xmlData);
      const tradesList = parsed.FlexQueryResponse?.FlexStatements?.[0]?.FlexStatement?.[0]?.Trades?.[0]?.Trade;

      if (!tradesList || tradesList.length === 0) {
        logger.info('No trades found in Flex report');
        return [];
      }

      return tradesList.map((trade: { $: Record<string, string> }) => {
        const attrs = trade.$;
        return {
          symbol: attrs.symbol || '',
          tradeID: attrs.tradeID || '',
          ibOrderID: attrs.ibOrderID || '',
          tradeDate: attrs.tradeDate || '',
          tradeTime: attrs.tradeTime || '',
          buySell: attrs.buySell === 'BUY' ? 'BUY' : 'SELL',
          quantity: parseFloat(attrs.quantity || '0'),
          tradePrice: parseFloat(attrs.tradePrice || '0'),
          ibCommission: parseFloat(attrs.ibCommission || '0'),
          ibCommissionCurrency: attrs.ibCommissionCurrency || 'USD',
          netCash: parseFloat(attrs.netCash || '0'),
          closePrice: parseFloat(attrs.closePrice || '0'),
          fifoPnlRealized: parseFloat(attrs.fifoPnlRealized || '0'),
          assetCategory: attrs.assetCategory || 'STK', // STK, OPT, FUT, CASH
        };
      });
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to parse trades from Flex report', error);
      throw new Error(`Trade parsing failed: ${errorMessage}`);
    }
  }

  async parsePositions(xmlData: string): Promise<FlexPosition[]> {
    try {
      const parsed = await parseStringPromise(xmlData);
      const positionsList = parsed.FlexQueryResponse?.FlexStatements?.[0]?.FlexStatement?.[0]?.OpenPositions?.[0]?.OpenPosition;

      if (!positionsList || positionsList.length === 0) {
        logger.info('No positions found in Flex report');
        return [];
      }

      return positionsList.map((position: { $: Record<string, string> }) => {
        const attrs = position.$;
        return {
          symbol: attrs.symbol || '',
          position: parseFloat(attrs.position || '0'),
          markPrice: parseFloat(attrs.markPrice || '0'),
          positionValue: parseFloat(attrs.positionValue || '0'),
          openPrice: parseFloat(attrs.openPrice || '0'),
          costBasisPrice: parseFloat(attrs.costBasisPrice || '0'),
          fifoPnlUnrealized: parseFloat(attrs.fifoPnlUnrealized || '0'),
        };
      });
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to parse positions from Flex report', error);
      throw new Error(`Position parsing failed: ${errorMessage}`);
    }
  }

  async parseCashTransactions(xmlData: string): Promise<FlexCashTransaction[]> {
    try {
      const parsed = await parseStringPromise(xmlData);
      const cashList = parsed.FlexQueryResponse?.FlexStatements?.[0]?.FlexStatement?.[0]?.CashTransactions?.[0]?.CashTransaction;

      if (!cashList || cashList.length === 0) {
        logger.info('No cash transactions found in Flex report');
        return [];
      }

      return cashList.map((cash: { $: Record<string, string> }) => {
        const attrs = cash.$;
        return {
          symbol: attrs.symbol || '',
          date: attrs.dateTime || attrs.reportDate || '',
          type: attrs.type || '',
          amount: parseFloat(attrs.amount || '0'),
          currency: attrs.currency || 'USD',
          description: attrs.description || '',
        };
      });
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to parse cash transactions from Flex report', error);
      throw new Error(`Cash transaction parsing failed: ${errorMessage}`);
    }
  }

  async parseAccountSummary(xmlData: string): Promise<FlexAccountSummary[]> {
    try {
      const parsed = await parseStringPromise(xmlData);
      const flexStatement = parsed.FlexQueryResponse?.FlexStatements?.[0]?.FlexStatement?.[0];
      if (!flexStatement) {return [];}

      // DEBUG: Log all top-level keys in flexStatement
      logger.info('IBKR FlexStatement structure:', {
        keys: Object.keys(flexStatement),
        hasEquitySummaryByReportDateInBase: !!flexStatement.EquitySummaryByReportDateInBase,
        hasEquitySummaryInBase: !!flexStatement.EquitySummaryInBase
      });

      let dataList = flexStatement.EquitySummaryByReportDateInBase
        || flexStatement.AccountInformation?.[0]?.AccountInformation;

      if (!dataList && flexStatement.EquitySummaryInBase) {
        dataList = flexStatement.EquitySummaryInBase[0]?.EquitySummaryByReportDateInBase;
      }

      if (!dataList || dataList.length === 0) {
        logger.info('No account summary data found in Flex report');
        return [];
      }

      // DEBUG: Log first and last entries to understand date range
      const firstEntry = dataList[0]?.$;
      const lastEntry = dataList[dataList.length - 1]?.$;
      logger.info('IBKR Data Range:', {
        totalEntries: dataList.length,
        firstDate: firstEntry?.reportDate,
        lastDate: lastEntry?.reportDate,
        lastTotal: lastEntry?.total,
        lastCash: lastEntry?.cash
      });

      return dataList.map((info: { $: Record<string, string> }, index: number) => {
        const attrs = info.$;

        // DEBUG: Log all available attributes for first entry to identify field names
        if (index === dataList.length - 1) {
          logger.info('IBKR EquitySummary attributes (latest entry):', { attrs });
        }

        const netLiquidation = parseFloat(
          attrs.total || attrs.netLiquidation || attrs.netLiquidationValue || attrs.equityWithLoanValue || attrs.equity || '0'
        );

        return {
          date: attrs.reportDate || attrs.toDate || '',
          cash: parseFloat(attrs.cash || '0'),
          stockValue: parseFloat(attrs.stock || attrs.stockMarketValue || '0'),
          optionValue: parseFloat(attrs.options || attrs.optionMarketValue || '0'),
          // IBKR uses 'commodities' for futures/commodities equity value
          commodityValue: parseFloat(attrs.commodities || attrs.commodityOptions || attrs.commodityMarketValue || '0'),
          netLiquidationValue: netLiquidation,
          unrealizedPnL: parseFloat(attrs.forexCfdUnrealizedPl || attrs.unrealizedPnL || '0'),
          realizedPnL: parseFloat(attrs.realizedPnL || '0'),
        };
      });
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error);
      logger.error('Failed to parse account summary from Flex report', error);
      throw new Error(`Account summary parsing failed: ${errorMessage}`);
    }
  }

  async testConnection(token: string, queryId: string): Promise<boolean> {
    try {
      const referenceCode = await this.requestFlexReport(token, queryId);
      await this.getFlexStatement(token, referenceCode);
      logger.info('Flex connection test successful');
      return true;
    } catch (error: unknown) {
      logger.error('Flex connection test failed', error);
      return false;
    }
  }

  async getFlexDataCached(token: string, queryId: string): Promise<string> {
    const cacheKey = `${token}:${queryId}`;
    const now = Date.now();

    const cached = this.flexCache.get(cacheKey);
    if (cached && (now - cached.timestamp) < this.CACHE_TTL_MS) {
      const age = Math.round((now - cached.timestamp) / 1000);
      logger.debug(`Flex cache HIT (age: ${age}s)`, { queryId });
      return cached.xmlData;
    }

    logger.debug('Flex cache MISS - fetching from API', { queryId });

    const referenceCode = await this.requestFlexReport(token, queryId);
    const xmlData = await this.getFlexStatement(token, referenceCode);

    this.flexCache.set(cacheKey, { xmlData, timestamp: now });

    // Cleanup entries older than 1 hour (well past the 30min TTL)
    for (const [key, value] of this.flexCache.entries()) {
      if (now - value.timestamp > 60 * 60 * 1000) {
        this.flexCache.delete(key);
      }
    }

    logger.debug('Flex data cached', { queryId, cacheSize: this.flexCache.size });
    return xmlData;
  }
}
