# Exchange Connector Architecture

## Overview

The exchange connector system provides a unified interface for collecting trading data from multiple exchanges and brokers. The architecture uses **abstraction layers** to reduce code duplication and support 100+ exchanges.

---

## Architecture Diagram

```
IExchangeConnector (interface)
        ↑
        │
BaseExchangeConnector (abstract)
        ↑
        ├─────────────────────────────┬────────────────────────┐
        │                             │                        │
CryptoExchangeConnector      RestBrokerConnector      IbkrFlexConnector
    (abstract)                   (abstract)              (concrete)
        │                             │
        │                             │
CcxtExchangeConnector          AlpacaConnector
    (concrete)                   (concrete)
        │
        │
  100+ Crypto Exchanges
  (Binance, Bitget, MEXC, OKX, Bybit, etc.)
```

---

## Layer Responsibilities

### 1. **BaseExchangeConnector** (abstract)

**Purpose:** Foundation for ALL connectors

**Provides:**
- ✅ Error handling (`withErrorHandling()`)
- ✅ Logging infrastructure
- ✅ Helper utilities (`parseFloat()`, `toDate()`, `isInDateRange()`)
- ✅ Balance creation (`createBalanceData()`)
- ✅ Default capital flows implementation (returns `[]`)

**Location:** `src/external/base/BaseExchangeConnector.ts`

---

### 2. **CryptoExchangeConnector** (abstract)

**Purpose:** Base for cryptocurrency exchanges

**Provides:**
- Default currency: `USDT`
- Timestamp conversion (milliseconds)
- Common crypto features support
- Status mapping helpers

**Location:** `src/external/base/CryptoExchangeConnector.ts`

---

### 3. **CcxtExchangeConnector** (concrete)

**Purpose:** Unified connector for 100+ crypto exchanges via CCXT library

**Supported Exchanges:**
- Binance Perpetuals (`binanceusdm`)
- Bitget Futures (`bitget`)
- MEXC Futures (`mexc`)
- OKX Futures (`okx`)
- Bybit Futures (`bybit`)
- KuCoin Futures (`kucoinfutures`)
- And 100+ more...

**Key Features:**
- ✅ Single implementation for all crypto exchanges
- ✅ CCXT handles API differences
- ✅ Built-in rate limiting
- ✅ Automatic retry logic
- ✅ Community-maintained (regular updates)

**Location:** `src/external/connectors/CcxtExchangeConnector.ts`

**Example:**
```typescript
// Binance Perpetuals
const binance = new CcxtExchangeConnector('binanceusdm', credentials);

// Bitget Futures
const bitget = new CcxtExchangeConnector('bitget', credentials);

// Any CCXT-supported exchange
const exchange = new CcxtExchangeConnector('okx', credentials);
```

---

### 4. **RestBrokerConnector** (abstract)

**Purpose:** Base for stock brokers using standard REST APIs

**Provides:**
- HTTP request wrapper (`makeRequest()`)
- Authentication abstraction (`getAuthHeaders()`)
- Default currency: `USD`
- ISO date conversion helpers

**Subclasses:**
- `AlpacaConnector` - API Key authentication
- (Future: `TdAmeritradeConnector` - OAuth 2.0)
- (Future: `EtradeConnector` - OAuth 1.0a)

**Location:** `src/external/base/RestBrokerConnector.ts`

---

### 5. **IbkrFlexConnector** (concrete)

**Purpose:** Interactive Brokers Flex Query API (standalone)

**Why standalone?**
- ❌ Unique 2-step async process (request → poll → fetch XML)
- ❌ No other broker uses this pattern
- ❌ YAGNI principle: No need for abstraction with only 1 implementation

**Key Features:**
- ✅ Private helper `fetchFlexData()` to reduce duplication
- ✅ Uses `withErrorHandling()` from BaseExchangeConnector
- ✅ T+1 data (historical, not real-time)

**Location:** `src/external/connectors/IbkrFlexConnector.ts`

---

### 6. **AlpacaConnector** (concrete)

**Purpose:** Alpaca Markets stock trading

**Features:**
- Inherits from `RestBrokerConnector`
- API Key authentication
- Stocks + Crypto support
- Real-time data

**Location:** `src/external/connectors/AlpacaConnector.ts`

---

## Factory Pattern

**ExchangeConnectorFactory** provides a simple way to instantiate connectors:

```typescript
// Usage
const credentials: ExchangeCredentials = {
  exchange: 'binance',
  apiKey: 'xxx',
  apiSecret: 'yyy',
};

const connector = ExchangeConnectorFactory.create(credentials);
const balance = await connector.getBalance();
```

**Factory Logic:**
1. Check if exchange is a stock broker (IBKR, Alpaca) → use custom connector
2. Check if exchange is crypto (Binance, Bitget, etc.) → use `CcxtExchangeConnector`
3. Otherwise → throw error

**Location:** `src/external/factories/ExchangeConnectorFactory.ts`

---

## Benefits of This Architecture

### ✅ **Reduced Code Duplication**
- **Before:** 5 crypto connectors × 200 lines = 1,000 lines
- **After:** 1 CCXT connector × 250 lines = 250 lines
- **Reduction:** ~75% for crypto exchanges

### ✅ **100+ Exchanges Support**
- Adding a new crypto exchange = **0 lines of code** (just add to factory mapping)
- CCXT handles all API differences

### ✅ **Maintainability**
- Helpers centralized in `BaseExchangeConnector`
- Bug fixes in one place benefit all connectors
- Clear separation of concerns

### ✅ **Extensibility**
- Easy to add new stock brokers (inherit from `RestBrokerConnector`)
- Easy to add new crypto exchanges (already supported via CCXT)

### ✅ **YAGNI Respected**
- No over-engineering (e.g., no `FlexReportConnector` abstraction for 1 implementation)
- Abstractions only where there are 2-3+ similar cases

---

## Adding a New Exchange

### **Crypto Exchange (CCXT-supported)**

1. Check if exchange is in CCXT: https://github.com/ccxt/ccxt#supported-cryptocurrency-exchange-markets
2. Add mapping in `ExchangeConnectorFactory`:
   ```typescript
   private static readonly CCXT_EXCHANGES: Record<string, string> = {
     // ...
     'yourexchange': 'ccxt_exchange_id',
   };
   ```
3. Done! Factory will automatically use `CcxtExchangeConnector`

### **Stock Broker (REST API)**

1. Create new connector inheriting from `RestBrokerConnector`:
   ```typescript
   export class YourBrokerConnector extends RestBrokerConnector {
     protected apiBaseUrl = 'https://api.yourbroker.com/v1';

     protected async getAuthHeaders(): Promise<Record<string, string>> {
       // Implement authentication
     }

     async getBalance(): Promise<BalanceData> {
       // Implement using this.makeRequest()
     }
     // ...
   }
   ```

2. Add to factory:
   ```typescript
   private static readonly CUSTOM_BROKERS = ['ibkr', 'alpaca', 'yourbroker'];

   private static createCustomBrokerConnector(...) {
     case 'yourbroker':
       return new YourBrokerConnector(credentials);
   }
   ```

### **Custom Exchange (non-CCXT, non-REST standard)**

1. Inherit from `BaseExchangeConnector` directly
2. Implement all required methods
3. Add to factory as custom broker

---

## Migration Path

### **Old Connectors (deprecated)**

These connectors are **deprecated** but still exist for backward compatibility:
- ❌ `BitgetConnector.ts` → Use `CcxtExchangeConnector('bitget')` instead
- ❌ `BinanceConnector.ts` → Use `CcxtExchangeConnector('binanceusdm')` instead
- ❌ `MexcConnector.ts` → Use `CcxtExchangeConnector('mexc')` instead

**Migration:** Simply use the factory, which automatically routes to CCXT for these exchanges.

---

## Testing

### **Unit Tests**

Test the abstraction layers:
```typescript
// Test BaseExchangeConnector helpers
describe('BaseExchangeConnector', () => {
  it('should create balance data correctly', () => {
    const balance = connector.createBalanceData(1000, 1200, 'USDT');
    expect(balance.unrealizedPnl).toBe(200);
  });
});

// Test CcxtExchangeConnector
describe('CcxtExchangeConnector', () => {
  it('should fetch balance for Binance', async () => {
    const connector = new CcxtExchangeConnector('binanceusdm', credentials);
    const balance = await connector.getBalance();
    expect(balance).toBeDefined();
  });
});
```

### **Integration Tests**

Test via factory:
```typescript
describe('ExchangeConnectorFactory', () => {
  it('should create CCXT connector for Binance', () => {
    const connector = ExchangeConnectorFactory.create({ exchange: 'binance', ... });
    expect(connector).toBeInstanceOf(CcxtExchangeConnector);
  });

  it('should create IBKR connector', () => {
    const connector = ExchangeConnectorFactory.create({ exchange: 'ibkr', ... });
    expect(connector).toBeInstanceOf(IbkrFlexConnector);
  });
});
```

---

## Future Enhancements

### **Planned:**
- [ ] Add `TdAmeritradeConnector` (OAuth 2.0)
- [ ] Add `EtradeConnector` (OAuth 1.0a)
- [ ] Add more CCXT exchanges to factory mapping (OKX, Bybit, etc.)
- [ ] Implement caching layer for `CcxtExchangeConnector`

### **Not Planned:**
- ❌ `FlexReportConnector` abstraction (only IBKR uses Flex)
- ❌ Custom connectors for crypto exchanges (use CCXT instead)

---

## References

- **CCXT Documentation:** https://docs.ccxt.com/
- **CCXT Supported Exchanges:** https://github.com/ccxt/ccxt#supported-cryptocurrency-exchange-markets
- **IBKR Flex Query API:** https://www.interactivebrokers.com/campus/ibkr-api-page/flex-web-service/
- **Alpaca API:** https://alpaca.markets/docs/api-references/trading-api/

---

## Summary

| Layer | Purpose | Implementations | LOC | Exchanges Supported |
|-------|---------|-----------------|-----|---------------------|
| BaseExchangeConnector | Foundation | 1 (abstract) | ~200 | N/A |
| CryptoExchangeConnector | Crypto base | 1 (abstract) | ~70 | N/A |
| **CcxtExchangeConnector** | **Unified crypto** | **1 (concrete)** | **~250** | **100+** |
| RestBrokerConnector | Broker base | 1 (abstract) | ~130 | N/A |
| IbkrFlexConnector | IBKR Flex | 1 (concrete) | ~200 | 1 |
| AlpacaConnector | Alpaca | 1 (concrete) | ~150 | 1 |
| **Total** |  | **6 files** | **~1,000** | **102+** |

**Before architecture:** ~1,500 lines, 5 crypto connectors, 5 exchanges
**After architecture:** ~1,000 lines, 1 crypto connector, 102+ exchanges

**Reduction:** ~33% LOC, **+2,000% exchanges supported**
