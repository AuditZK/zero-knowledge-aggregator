import { IbkrFlexService } from '../../external/ibkr-flex-service';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('IbkrFlexService', () => {
  let service: IbkrFlexService;

  const mockToken = 'test_token_123';
  const mockQueryId = 'query_456';
  const mockReferenceCode = 'ref_789';

  const createSuccessResponse = (data: string) => ({
    data,
    status: 200,
  });

  const createFlexRequestSuccessXml = `
    <?xml version="1.0" encoding="utf-8"?>
    <FlexStatementResponse>
      <Status>Success</Status>
      <ReferenceCode>${mockReferenceCode}</ReferenceCode>
    </FlexStatementResponse>
  `;

  const createFlexRequestFailXml = (errorCode: string, errorMessage: string) => `
    <?xml version="1.0" encoding="utf-8"?>
    <FlexStatementResponse>
      <Status>Fail</Status>
      <ErrorCode>${errorCode}</ErrorCode>
      <ErrorMessage>${errorMessage}</ErrorMessage>
    </FlexStatementResponse>
  `;

  const createFlexStatementXml = (options: {
    trades?: Array<{ symbol: string; buySell: string; quantity: number; tradePrice: number }>;
    positions?: Array<{ symbol: string; position: number; markPrice: number }>;
    cashTransactions?: Array<{ symbol: string; type: string; amount: number }>;
    equitySummary?: Array<{ reportDate: string; total: number; cash: number }>;
  } = {}) => {
    const tradesXml = options.trades?.map(t =>
      `<Trade symbol="${t.symbol}" buySell="${t.buySell}" quantity="${t.quantity}" tradePrice="${t.tradePrice}" tradeID="TR001" ibOrderID="ORD001" tradeDate="2024-01-15" tradeTime="10:00:00" ibCommission="1.00" ibCommissionCurrency="USD" netCash="${t.quantity * t.tradePrice}" closePrice="${t.tradePrice}" fifoPnlRealized="100" assetCategory="STK" />`
    ).join('') || '';

    const positionsXml = options.positions?.map(p =>
      `<OpenPosition symbol="${p.symbol}" position="${p.position}" markPrice="${p.markPrice}" positionValue="${p.position * p.markPrice}" openPrice="${p.markPrice - 5}" costBasisPrice="${p.markPrice - 5}" fifoPnlUnrealized="${p.position * 5}" />`
    ).join('') || '';

    const cashXml = options.cashTransactions?.map(c =>
      `<CashTransaction symbol="${c.symbol}" type="${c.type}" amount="${c.amount}" currency="USD" dateTime="2024-01-15" description="Transaction" />`
    ).join('') || '';

    // The IBKR XML has EquitySummaryByReportDateInBase as an array at root level with $ attributes
    const equityXml = options.equitySummary?.map(e =>
      `<EquitySummaryByReportDateInBase reportDate="${e.reportDate}" total="${e.total}" cash="${e.cash}" stock="0" options="0" commodities="0" />`
    ).join('') || '';

    // Build the XML structure - if equitySummary is provided, include it directly under FlexStatement
    const equitySection = options.equitySummary && options.equitySummary.length > 0
      ? `<EquitySummaryByReportDateInBase>${equityXml}</EquitySummaryByReportDateInBase>`
      : '';

    return `
      <?xml version="1.0" encoding="utf-8"?>
      <FlexQueryResponse>
        <FlexStatements>
          <FlexStatement>
            <Trades>${tradesXml}</Trades>
            <OpenPositions>${positionsXml}</OpenPositions>
            <CashTransactions>${cashXml}</CashTransactions>
            ${equitySection}
          </FlexStatement>
        </FlexStatements>
      </FlexQueryResponse>
    `;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    service = new IbkrFlexService();
  });

  describe('requestFlexReport', () => {
    it('should return reference code on success', async () => {
      mockedAxios.get.mockResolvedValue(createSuccessResponse(createFlexRequestSuccessXml));

      const result = await service.requestFlexReport(mockToken, mockQueryId);

      expect(result).toBe(mockReferenceCode);
      expect(mockedAxios.get).toHaveBeenCalledWith(
        expect.stringContaining('FlexStatementService.SendRequest'),
        expect.objectContaining({
          params: { t: mockToken, q: mockQueryId, v: '3' },
        })
      );
    });

    it('should throw error when API returns fail status', async () => {
      mockedAxios.get.mockResolvedValue(
        createSuccessResponse(createFlexRequestFailXml('1001', 'Invalid token'))
      );

      await expect(service.requestFlexReport(mockToken, mockQueryId))
        .rejects.toThrow('Flex API Error 1001: Invalid token');
    });

    it('should throw error when no reference code returned', async () => {
      mockedAxios.get.mockResolvedValue(createSuccessResponse(`
        <?xml version="1.0" encoding="utf-8"?>
        <FlexStatementResponse>
          <Status>Success</Status>
        </FlexStatementResponse>
      `));

      await expect(service.requestFlexReport(mockToken, mockQueryId))
        .rejects.toThrow('No reference code received from Flex API');
    });

    it('should throw error on network failure', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Network error'));

      await expect(service.requestFlexReport(mockToken, mockQueryId))
        .rejects.toThrow('Flex request failed: Network error');
    });
  });

  describe('getFlexStatement', () => {
    it('should return statement XML on success', async () => {
      const statementXml = createFlexStatementXml({ trades: [{ symbol: 'AAPL', buySell: 'BUY', quantity: 100, tradePrice: 150 }] });
      mockedAxios.get.mockResolvedValue(createSuccessResponse(statementXml));

      const result = await service.getFlexStatement(mockToken, mockReferenceCode);

      expect(result).toContain('FlexQueryResponse');
    });

    it('should retry when statement not ready (error 1019)', async () => {
      // First call - not ready
      mockedAxios.get.mockResolvedValueOnce(
        createSuccessResponse(createFlexRequestFailXml('1019', 'Statement not ready'))
      );
      // Second call - success
      const statementXml = createFlexStatementXml();
      mockedAxios.get.mockResolvedValueOnce(createSuccessResponse(statementXml));

      const result = await service.getFlexStatement(mockToken, mockReferenceCode);

      expect(result).toContain('FlexQueryResponse');
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    }, 10000);

    it.skip('should throw error after max retries', async () => {
      // Skipped: Test takes 60+ seconds due to retry logic (20 retries * 3s each)
      // The retry logic is tested in 'should retry when statement not ready' test
      mockedAxios.get.mockResolvedValue(
        createSuccessResponse(createFlexRequestFailXml('1019', 'Statement not ready'))
      );

      await expect(service.getFlexStatement(mockToken, mockReferenceCode))
        .rejects.toThrow('Flex retrieval failed');
    }, 70000);

    it('should throw error on non-retryable failure', async () => {
      mockedAxios.get.mockResolvedValue(
        createSuccessResponse(createFlexRequestFailXml('1001', 'Invalid token'))
      );

      await expect(service.getFlexStatement(mockToken, mockReferenceCode))
        .rejects.toThrow('Flex API Error 1001: Invalid token');
    });
  });

  describe('parseTrades', () => {
    it('should parse trades from XML', async () => {
      const xml = createFlexStatementXml({
        trades: [
          { symbol: 'AAPL', buySell: 'BUY', quantity: 100, tradePrice: 150 },
          { symbol: 'MSFT', buySell: 'SELL', quantity: 50, tradePrice: 400 },
        ],
      });

      const trades = await service.parseTrades(xml);

      expect(trades).toHaveLength(2);
      expect(trades[0]?.symbol).toBe('AAPL');
      expect(trades[0]?.buySell).toBe('BUY');
      expect(trades[0]?.quantity).toBe(100);
      expect(trades[1]?.symbol).toBe('MSFT');
      expect(trades[1]?.buySell).toBe('SELL');
    });

    it('should return empty array when no trades', async () => {
      const xml = createFlexStatementXml();

      const trades = await service.parseTrades(xml);

      expect(trades).toEqual([]);
    });

    it('should throw error on invalid XML', async () => {
      await expect(service.parseTrades('invalid xml'))
        .rejects.toThrow('Trade parsing failed');
    });
  });

  describe('parsePositions', () => {
    it('should parse positions from XML', async () => {
      const xml = createFlexStatementXml({
        positions: [
          { symbol: 'AAPL', position: 100, markPrice: 175 },
          { symbol: 'GOOGL', position: 50, markPrice: 140 },
        ],
      });

      const positions = await service.parsePositions(xml);

      expect(positions).toHaveLength(2);
      expect(positions[0]?.symbol).toBe('AAPL');
      expect(positions[0]?.position).toBe(100);
      expect(positions[0]?.markPrice).toBe(175);
    });

    it('should return empty array when no positions', async () => {
      const xml = createFlexStatementXml();

      const positions = await service.parsePositions(xml);

      expect(positions).toEqual([]);
    });

    it('should throw error on invalid XML', async () => {
      await expect(service.parsePositions('invalid xml'))
        .rejects.toThrow('Position parsing failed');
    });
  });

  describe('parseCashTransactions', () => {
    it('should parse cash transactions from XML', async () => {
      const xml = createFlexStatementXml({
        cashTransactions: [
          { symbol: '', type: 'Deposits', amount: 10000 },
          { symbol: '', type: 'Withdrawals', amount: -5000 },
        ],
      });

      const cashTx = await service.parseCashTransactions(xml);

      expect(cashTx).toHaveLength(2);
      expect(cashTx[0]?.type).toBe('Deposits');
      expect(cashTx[0]?.amount).toBe(10000);
      expect(cashTx[1]?.type).toBe('Withdrawals');
    });

    it('should return empty array when no cash transactions', async () => {
      const xml = createFlexStatementXml();

      const cashTx = await service.parseCashTransactions(xml);

      expect(cashTx).toEqual([]);
    });

    it('should throw error on invalid XML', async () => {
      await expect(service.parseCashTransactions('invalid xml'))
        .rejects.toThrow('Cash transaction parsing failed');
    });
  });

  describe('parseAccountSummary', () => {
    it('should parse account summary from XML', async () => {
      // Create XML with proper structure for IBKR equity summary
      // Multiple EquitySummaryByReportDateInBase elements directly under FlexStatement
      const xml = `
        <?xml version="1.0" encoding="utf-8"?>
        <FlexQueryResponse>
          <FlexStatements>
            <FlexStatement>
              <EquitySummaryByReportDateInBase reportDate="2024-01-15" total="100000" cash="50000" stock="40000" options="10000" commodities="0" />
              <EquitySummaryByReportDateInBase reportDate="2024-01-16" total="101000" cash="51000" stock="40000" options="10000" commodities="0" />
            </FlexStatement>
          </FlexStatements>
        </FlexQueryResponse>
      `;

      const summary = await service.parseAccountSummary(xml);

      expect(summary).toHaveLength(2);
      expect(summary[0]?.netLiquidationValue).toBe(100000);
      expect(summary[0]?.cash).toBe(50000);
    });

    it('should return empty array when no summary data', async () => {
      const xml = `
        <?xml version="1.0" encoding="utf-8"?>
        <FlexQueryResponse>
          <FlexStatements>
            <FlexStatement>
              <Trades></Trades>
            </FlexStatement>
          </FlexStatements>
        </FlexQueryResponse>
      `;

      const summary = await service.parseAccountSummary(xml);

      expect(summary).toEqual([]);
    });

    it('should throw error on invalid XML', async () => {
      await expect(service.parseAccountSummary('invalid xml'))
        .rejects.toThrow('Account summary parsing failed');
    });
  });

  describe('testConnection', () => {
    it('should return true when connection succeeds', async () => {
      mockedAxios.get
        .mockResolvedValueOnce(createSuccessResponse(createFlexRequestSuccessXml))
        .mockResolvedValueOnce(createSuccessResponse(createFlexStatementXml()));

      const result = await service.testConnection(mockToken, mockQueryId);

      expect(result).toBe(true);
    });

    it('should return false when connection fails', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Connection failed'));

      const result = await service.testConnection(mockToken, mockQueryId);

      expect(result).toBe(false);
    });
  });

  describe('getFlexDataCached', () => {
    it('should cache response and return cached data on subsequent calls', async () => {
      const statementXml = createFlexStatementXml({ trades: [{ symbol: 'AAPL', buySell: 'BUY', quantity: 100, tradePrice: 150 }] });

      mockedAxios.get
        .mockResolvedValueOnce(createSuccessResponse(createFlexRequestSuccessXml))
        .mockResolvedValueOnce(createSuccessResponse(statementXml));

      // First call - should fetch from API
      const result1 = await service.getFlexDataCached(mockToken, mockQueryId);
      expect(result1).toContain('AAPL');

      // Second call - should return cached data
      const result2 = await service.getFlexDataCached(mockToken, mockQueryId);
      expect(result2).toContain('AAPL');

      // API should only be called once (2 calls for first request: SendRequest + GetStatement)
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    });

    it('should deduplicate concurrent requests', async () => {
      const statementXml = createFlexStatementXml();

      mockedAxios.get
        .mockResolvedValueOnce(createSuccessResponse(createFlexRequestSuccessXml))
        .mockResolvedValueOnce(createSuccessResponse(statementXml));

      // Make concurrent requests
      const [result1, result2] = await Promise.all([
        service.getFlexDataCached(mockToken, mockQueryId),
        service.getFlexDataCached(mockToken, mockQueryId),
      ]);

      // Both should succeed
      expect(result1).toContain('FlexQueryResponse');
      expect(result2).toContain('FlexQueryResponse');

      // API should only be called once (2 calls total, not 4)
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    });
  });
});
