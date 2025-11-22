import { injectable } from 'tsyringe';
import axios from 'axios';
import { parseStringPromise } from 'xml2js';
import { getLogger } from '../utils/logger.service';

const logger = getLogger('IbkrFlexService');

/**
 * IBKR Flex Web Service
 *
 * API Documentation: https://www.interactivebrokers.com/en/software/am/am/reports/flex_web_service_version_3.htm
 *
 * Flow:
 * 1. SendRequest with token and query ID → get reference code
 * 2. GetStatement with reference code → get XML report
 * 3. Parse XML to extract trades, positions, cash flows
 */

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
  // Using ndcdyn endpoint (faster regional server - confirmed <1s response time)
  // Alternative: gdcdyn (global) can timeout for large reports
  private readonly baseUrl = 'https://ndcdyn.interactivebrokers.com/Universal/servlet';

  // Cache Flex XML responses to avoid duplicate API calls
  // Key: `${token}:${queryId}` → Value: {xmlData, timestamp}
  private readonly flexCache = new Map<string, FlexCache>();
  private readonly CACHE_TTL_MS = 60 * 1000; // 60 seconds

  /**
   * Step 1: Request a Flex report
   * Returns a reference code to retrieve the report
   */
  async requestFlexReport(token: string, queryId: string): Promise<string> {
    const startTime = Date.now();

    try {
      logger.info('Requesting Flex report', { queryId });

      const response = await axios.get(`${this.baseUrl}/FlexStatementService.SendRequest`, {
        params: {
          t: token,
          q: queryId,
          v: '3', // API version 3
        },
        timeout: 30000,
      });

      const xmlData = response.data;
      const parsed = await parseStringPromise(xmlData);

      // Check for errors
      if (parsed.FlexStatementResponse?.Status?.[0] === 'Fail') {
        const errorCode = parsed.FlexStatementResponse?.ErrorCode?.[0];
        const errorMessage = parsed.FlexStatementResponse?.ErrorMessage?.[0];
        throw new Error(`Flex API Error ${errorCode}: ${errorMessage}`);
      }

      const referenceCode = parsed.FlexStatementResponse?.ReferenceCode?.[0];

      if (!referenceCode) {
        throw new Error('No reference code received from Flex API');
      }

      const duration = ((Date.now() - startTime) / 1000).toFixed(3);
      logger.info(`Flex report requested successfully (${duration}s)`, { referenceCode });
      return referenceCode;

    } catch (error: any) {
      logger.error('Failed to request Flex report', error);
      throw new Error(`Flex request failed: ${error.message}`);
    }
  }

  /**
   * Step 2: Retrieve the Flex report using reference code
   * Returns the XML report data
   */
  async getFlexStatement(token: string, referenceCode: string): Promise<string> {
    const startTime = Date.now();

    try {
      logger.info('Retrieving Flex statement', { referenceCode });

      // Retry logic - ndcdyn endpoint typically responds in <1s
      const maxRetries = 20; // Reduced from 30 since ndcdyn is much faster
      const retryDelay = 3000; // 3 seconds (matching Python script)

      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        const response = await axios.get(`${this.baseUrl}/FlexStatementService.GetStatement`, {
          params: {
            t: token,
            q: referenceCode,
            v: '3',
          },
          timeout: 30000,
        });

        const xmlData = response.data;

        // Quick check: If response contains FlexQueryResponse, report is ready immediately
        if (xmlData.includes('<FlexQueryResponse')) {
          const duration = ((Date.now() - startTime) / 1000).toFixed(3);
          logger.info(`Flex statement retrieved successfully after ${attempt} attempts (${duration}s)`);
          return xmlData;
        }

        // Otherwise, parse XML to check status
        const parsed = await parseStringPromise(xmlData);

        // Check if report is ready
        const status = parsed.FlexStatementResponse?.Status?.[0];

        if (status === 'Success') {
          const duration = ((Date.now() - startTime) / 1000).toFixed(3);
          logger.info(`Flex statement retrieved successfully after ${attempt} attempts (${duration}s)`);
          return xmlData;
        } else if (status === 'Fail') {
          const errorCode = parsed.FlexStatementResponse?.ErrorCode?.[0];
          const errorMessage = parsed.FlexStatementResponse?.ErrorMessage?.[0];

          // Error 1019 = Statement generation in progress, retry
          if (errorCode === '1019' && attempt < maxRetries) {
            logger.info(`Statement not ready, retrying in ${retryDelay}ms (attempt ${attempt}/${maxRetries})`);
            await this.sleep(retryDelay);
            continue;
          }

          throw new Error(`Flex API Error ${errorCode}: ${errorMessage}`);
        }
      }

      throw new Error('Flex statement generation timeout - report not ready after retries');

    } catch (error: any) {
      logger.error('Failed to get Flex statement', error);
      throw new Error(`Flex retrieval failed: ${error.message}`);
    }
  }

  /**
   * Parse trades from Flex XML report
   */
  async parseTrades(xmlData: string): Promise<FlexTrade[]> {
    try {
      const parsed = await parseStringPromise(xmlData);
      const trades: FlexTrade[] = [];

      const tradesList = parsed.FlexQueryResponse?.FlexStatements?.[0]?.FlexStatement?.[0]?.Trades?.[0]?.Trade;

      if (!tradesList || tradesList.length === 0) {
        logger.info('No trades found in Flex report');
        return [];
      }

      for (const trade of tradesList) {
        const attrs = trade.$; // XML attributes

        trades.push({
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
        });
      }

      logger.info(`Parsed ${trades.length} trades from Flex report`);
      return trades;

    } catch (error: any) {
      logger.error('Failed to parse trades from Flex report', error);
      throw new Error(`Trade parsing failed: ${error.message}`);
    }
  }

  /**
   * Parse positions from Flex XML report
   */
  async parsePositions(xmlData: string): Promise<FlexPosition[]> {
    try {
      const parsed = await parseStringPromise(xmlData);
      const positions: FlexPosition[] = [];

      const positionsList = parsed.FlexQueryResponse?.FlexStatements?.[0]?.FlexStatement?.[0]?.OpenPositions?.[0]?.OpenPosition;

      if (!positionsList || positionsList.length === 0) {
        logger.info('No positions found in Flex report');
        return [];
      }

      for (const position of positionsList) {
        const attrs = position.$;

        positions.push({
          symbol: attrs.symbol || '',
          position: parseFloat(attrs.position || '0'),
          markPrice: parseFloat(attrs.markPrice || '0'),
          positionValue: parseFloat(attrs.positionValue || '0'),
          openPrice: parseFloat(attrs.openPrice || '0'),
          costBasisPrice: parseFloat(attrs.costBasisPrice || '0'),
          fifoPnlUnrealized: parseFloat(attrs.fifoPnlUnrealized || '0'),
        });
      }

      logger.info(`Parsed ${positions.length} positions from Flex report`);
      return positions;

    } catch (error: any) {
      logger.error('Failed to parse positions from Flex report', error);
      throw new Error(`Position parsing failed: ${error.message}`);
    }
  }

  /**
   * Parse cash transactions (deposits, withdrawals) from Flex XML report
   */
  async parseCashTransactions(xmlData: string): Promise<FlexCashTransaction[]> {
    try {
      const parsed = await parseStringPromise(xmlData);
      const transactions: FlexCashTransaction[] = [];

      const cashList = parsed.FlexQueryResponse?.FlexStatements?.[0]?.FlexStatement?.[0]?.CashTransactions?.[0]?.CashTransaction;

      if (!cashList || cashList.length === 0) {
        logger.info('No cash transactions found in Flex report');
        return [];
      }

      for (const cash of cashList) {
        const attrs = cash.$;

        transactions.push({
          symbol: attrs.symbol || '',
          date: attrs.dateTime || attrs.reportDate || '',
          type: attrs.type || '',
          amount: parseFloat(attrs.amount || '0'),
          currency: attrs.currency || 'USD',
          description: attrs.description || '',
        });
      }

      logger.info(`Parsed ${transactions.length} cash transactions from Flex report`);
      return transactions;

    } catch (error: any) {
      logger.error('Failed to parse cash transactions from Flex report', error);
      throw new Error(`Cash transaction parsing failed: ${error.message}`);
    }
  }

  /**
   * Parse account summary from Flex XML report
   */
  async parseAccountSummary(xmlData: string): Promise<FlexAccountSummary[]> {
    try {
      const parsed = await parseStringPromise(xmlData);
      const summaries: FlexAccountSummary[] = [];

      const flexStatement = parsed.FlexQueryResponse?.FlexStatements?.[0]?.FlexStatement?.[0];

      if (!flexStatement) {
        logger.warn('No FlexStatement found in response');
        logger.debug('XML preview:', xmlData.substring(0, 500));
        return [];
      }

      // Debug: Log available fields in FlexStatement
      logger.debug('FlexStatement keys:', Object.keys(flexStatement));

      // Try different Flex Query formats (different queries use different field names)
      let dataList = flexStatement.EquitySummaryByReportDateInBase // Format 1: Direct array
        || flexStatement.AccountInformation?.[0]?.AccountInformation; // Format 2: Nested AccountInformation

      // Format 3: EquitySummaryInBase → EquitySummaryByReportDateInBase (nested)
      if (!dataList && flexStatement.EquitySummaryInBase) {
        // XML structure: <EquitySummaryInBase><EquitySummaryByReportDateInBase>...</EquitySummaryByReportDateInBase></EquitySummaryInBase>
        logger.debug('Found EquitySummaryInBase, checking for nested EquitySummaryByReportDateInBase');
        const nested = flexStatement.EquitySummaryInBase[0]?.EquitySummaryByReportDateInBase;
        if (nested) {
          logger.debug('Found nested EquitySummaryByReportDateInBase with length:', nested.length);
          dataList = nested;
        }
      }

      if (!dataList || dataList.length === 0) {
        logger.info('No account summary data found in Flex report');
        return [];
      }

      // Debug: Check structure of first element
      logger.debug('dataList length:', dataList.length);
      logger.debug('First element keys:', dataList[0] ? Object.keys(dataList[0]) : 'empty');
      logger.debug('First element $:', dataList[0]?.$);

      for (const info of dataList) {
        const attrs = info.$;

        // DEBUG: Log all available fields for first summary
        if (summaries.length === 0) {
          logger.info('IBKR Flex Summary Fields:', {
            allFields: Object.keys(attrs),
            reportDate: attrs.reportDate,
            toDate: attrs.toDate,
            cash: attrs.cash,
            stock: attrs.stock,
            stockMarketValue: attrs.stockMarketValue,
            options: attrs.options,
            optionMarketValue: attrs.optionMarketValue,
            commodityOptions: attrs.commodityOptions,
            commodityMarketValue: attrs.commodityMarketValue,
            total: attrs.total,
            netLiquidation: attrs.netLiquidation,
            unrealizedPnL: attrs.unrealizedPnL,
            forexCfdUnrealizedPl: attrs.forexCfdUnrealizedPl,
            // Additional possible fields
            equity: attrs.equity,
            equityWithLoanValue: attrs.equityWithLoanValue,
            netLiquidationValue: attrs.netLiquidationValue,
          });
        }

        // Parse equity with multiple fallbacks to handle different Flex Query formats
        // Priority order: total > netLiquidation > netLiquidationValue > equityWithLoanValue > equity
        const netLiquidation = parseFloat(
          attrs.total ||
          attrs.netLiquidation ||
          attrs.netLiquidationValue ||
          attrs.equityWithLoanValue ||
          attrs.equity ||
          '0'
        );

        summaries.push({
          // EquitySummaryByReportDateInBase uses 'reportDate', AccountInformation uses 'toDate'
          date: attrs.reportDate || attrs.toDate || '',
          // EquitySummaryByReportDateInBase uses 'cash', AccountInformation uses 'cash'
          cash: parseFloat(attrs.cash || '0'),
          // EquitySummaryByReportDateInBase uses 'stock', AccountInformation uses 'stockMarketValue'
          stockValue: parseFloat(attrs.stock || attrs.stockMarketValue || '0'),
          // EquitySummaryByReportDateInBase uses 'options', AccountInformation uses 'optionMarketValue'
          optionValue: parseFloat(attrs.options || attrs.optionMarketValue || '0'),
          // EquitySummaryByReportDateInBase may have 'commodityOptions'
          commodityValue: parseFloat(attrs.commodityOptions || attrs.commodityMarketValue || '0'),
          // Multiple fallbacks for equity/netLiquidation field
          netLiquidationValue: netLiquidation,
          // EquitySummaryByReportDateInBase uses 'forexCfdUnrealizedPl', AccountInformation uses 'unrealizedPnL'
          unrealizedPnL: parseFloat(attrs.forexCfdUnrealizedPl || attrs.unrealizedPnL || '0'),
          realizedPnL: parseFloat(attrs.realizedPnL || '0'),
        });
      }

      logger.info(`Parsed ${summaries.length} account summaries from Flex report`);
      return summaries;

    } catch (error: any) {
      logger.error('Failed to parse account summary from Flex report', error);
      throw new Error(`Account summary parsing failed: ${error.message}`);
    }
  }

  /**
   * Test Flex connection by requesting and retrieving a simple report
   */
  async testConnection(token: string, queryId: string): Promise<boolean> {
    try {
      const referenceCode = await this.requestFlexReport(token, queryId);
      const xmlData = await this.getFlexStatement(token, referenceCode);

      // If we got here, connection is successful
      logger.info('Flex connection test successful');
      return true;

    } catch (error: any) {
      logger.error('Flex connection test failed', error);
      return false;
    }
  }

  /**
   * Get Flex data with caching to avoid duplicate API calls
   * Combines requestFlexReport + getFlexStatement with 60s cache
   *
   * Critical for IBKR rate limiting:
   * - Trade sync and snapshot creation happen simultaneously
   * - Both need the same Flex XML data
   * - Without cache: 2 API calls → Rate limit Error 1018
   * - With cache: 1 API call, second request uses cached XML
   */
  async getFlexDataCached(token: string, queryId: string): Promise<string> {
    const cacheKey = `${token}:${queryId}`;
    const now = Date.now();

    // Check cache
    const cached = this.flexCache.get(cacheKey);
    if (cached && (now - cached.timestamp) < this.CACHE_TTL_MS) {
      const age = Math.round((now - cached.timestamp) / 1000);
      logger.debug(`Flex cache HIT (age: ${age}s)`, { queryId });
      return cached.xmlData;
    }

    // Cache miss - fetch from API
    logger.debug('Flex cache MISS - fetching from API', { queryId });

    const referenceCode = await this.requestFlexReport(token, queryId);
    const xmlData = await this.getFlexStatement(token, referenceCode);

    // Store in cache
    this.flexCache.set(cacheKey, {
      xmlData,
      timestamp: now
    });

    // Clean old cache entries (>5 minutes old)
    for (const [key, value] of this.flexCache.entries()) {
      if (now - value.timestamp > 5 * 60 * 1000) {
        this.flexCache.delete(key);
      }
    }

    logger.debug('Flex data cached', { queryId, cacheSize: this.flexCache.size });

    return xmlData;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
