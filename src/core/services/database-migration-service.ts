import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { getLogger } from '../../utils/secure-enclave-logger';

const logger = getLogger('DatabaseMigrationService');

/**
 * SECURITY: Whitelist of allowed table names to prevent SQL injection
 * Only these tables can be modified by migrations
 */
const ALLOWED_TABLES = new Set([
  'migrations',
  'users',
  'exchange_connections',
  'sync_statuses',
  'trades',
  'positions',
  'hourly_returns',
  'snapshot_data',
  'data_encryption_keys',
  'sync_rate_limit_logs',
]);

/**
 * SECURITY: Whitelist of allowed column names to prevent SQL injection
 */
const ALLOWED_COLUMNS = new Set([
  'id', 'user_uid', 'userUid', 'exchange', 'label', 'symbol', 'side', 'type',
  'quantity', 'price', 'fees', 'fee_asset', 'feeAsset', 'timestamp', 'status',
  'matched_quantity', 'matchedQuantity', 'exchange_trade_id', 'exchangeTradeId',
  'created_at', 'createdAt', 'updated_at', 'updatedAt', 'credentials_hash',
  'encrypted_api_key', 'encrypted_api_secret', 'encrypted_passphrase',
  'is_active', 'isActive', 'last_sync_time', 'total_trades', 'error_message',
  'is_historical_complete', 'size', 'entry_price', 'entryPrice', 'mark_price',
  'markPrice', 'pnl', 'realized_pnl', 'realizedPnl', 'unrealized_pnl',
  'unrealizedPnl', 'percentage', 'net_profit', 'netProfit', 'closed_at',
  'hour', 'volume', 'total_quantity', 'totalQuantity', 'trades', 'return_pct',
  'returnPct', 'return_usd', 'returnUsd', 'total_fees', 'totalFees', 'matches',
  'name', 'applied_at',
]);

/**
 * Validates that a table name is in the allowed whitelist
 * @throws Error if table name is not allowed
 */
function validateTableName(tableName: string): void {
  // Allow _old suffix for migration tables
  const baseTableName = tableName.replace('_old', '');
  if (!ALLOWED_TABLES.has(baseTableName)) {
    throw new Error(`SECURITY: Table name "${tableName}" is not in the allowed whitelist`);
  }
  // Additional safety: ensure no SQL injection characters
  if (!/^[a-z_]+$/.test(tableName)) {
    throw new Error(`SECURITY: Invalid table name format "${tableName}"`);
  }
}

/**
 * Validates that a column name is in the allowed whitelist
 * @throws Error if column name is not allowed
 */
function validateColumnName(columnName: string): void {
  if (!ALLOWED_COLUMNS.has(columnName)) {
    throw new Error(`SECURITY: Column name "${columnName}" is not in the allowed whitelist`);
  }
  // Additional safety: ensure no SQL injection characters
  if (!/^[a-zA-Z_]+$/.test(columnName)) {
    throw new Error(`SECURITY: Invalid column name format "${columnName}"`);
  }
}

@injectable()
export class DatabaseMigrationService {
  constructor(@inject('PrismaClient') private readonly prisma: PrismaClient) {}

  async runMigrations(): Promise<void> {
    try {
      await this.createMigrationsTable();
      await this.addCredentialsHashColumn();
      await this.fixColumnNaming();
      await this.addClosedAtColumn();
      await this.addTypeColumnToTrades();
      await this.addStatusColumnToTrades();
      await this.addMatchedQuantityColumnToTrades();
      await this.fixIdColumnsToAutoIncrement();
    } catch (error) {
      logger.error('Database migration failed:', error);
      throw error;
    }
  }

  private async createMigrationsTable(): Promise<void> {
    await this.prisma.$executeRaw`CREATE TABLE IF NOT EXISTS migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`;
  }

  private async isMigrationApplied(name: string): Promise<boolean> {
    const result = await this.prisma.$queryRaw<{count: number}[]>`SELECT COUNT(*) as count FROM migrations WHERE name = ${name}`;
    return result[0]!.count > 0;
  }

  private async markMigrationApplied(name: string): Promise<void> {
    await this.prisma.$executeRaw`INSERT INTO migrations (name) VALUES (${name})`;
  }

  private async applyMigration(name: string, fn: () => Promise<void>): Promise<void> {
    if (await this.isMigrationApplied(name)) {return;}
    try { await fn(); await this.markMigrationApplied(name); }
    catch (error) { logger.error(`Migration ${name} failed:`, error); throw error; }
  }

  private async addCredentialsHashColumn(): Promise<void> {
    await this.applyMigration('add_credentials_hash_column', () => this.addColumn('exchange_connections', 'credentials_hash', 'TEXT'));
  }

  private async addClosedAtColumn(): Promise<void> {
    await this.applyMigration('add_closed_at_column', () => this.addColumn('positions', 'closed_at', 'TIMESTAMP DEFAULT NULL'));
  }

  private async addTypeColumnToTrades(): Promise<void> {
    await this.applyMigration('add_type_column_to_trades', async () => {
      await this.addColumn('trades', 'type', 'TEXT CHECK (type IN (\'buy\', \'sell\'))');
      await this.prisma.$executeRaw`UPDATE trades SET type = side WHERE type IS NULL`;
    });
  }

  private async addStatusColumnToTrades(): Promise<void> {
    await this.applyMigration('add_status_column_to_trades', async () => {
      await this.addColumn('trades', 'status', 'TEXT CHECK (status IN (\'pending\', \'matched\', \'partially_matched\')) DEFAULT \'pending\'');
      await this.prisma.$executeRaw`UPDATE trades SET status = 'matched' WHERE status IS NULL`;
    });
  }

  private async addMatchedQuantityColumnToTrades(): Promise<void> {
    await this.applyMigration('add_matched_quantity_column_to_trades', () => this.addColumn('trades', 'matched_quantity', 'DECIMAL(20,8) DEFAULT 0'));
  }

  private async addColumn(tableName: string, columnName: string, columnType: string): Promise<void> {
    // SECURITY: Validate inputs against whitelist before SQL execution
    validateTableName(tableName);
    validateColumnName(columnName);

    // Validate column type format (only alphanumeric, spaces, parentheses, and common SQL keywords)
    if (!/^[A-Z0-9() ,'_]+$/i.test(columnType)) {
      throw new Error(`SECURITY: Invalid column type format "${columnType}"`);
    }

    try {
      await this.prisma.$executeRawUnsafe(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnType}`);
    }
    catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      if (!errorMessage.includes('duplicate column name')) {
        logger.error(`Error adding column ${columnName} to ${tableName}`, err);
        throw err;
      }
    }
  }

  async columnExists(tableName: string, columnName: string): Promise<boolean> {
    // SECURITY: Validate table and column names against whitelist
    validateTableName(tableName);
    validateColumnName(columnName);

    const rows = await this.prisma.$queryRawUnsafe<{name: string}[]>(`PRAGMA table_info(${tableName})`);
    return rows.some(row => row.name === columnName);
  }

  async getTableInfo(tableName: string): Promise<{name: string; type: string}[]> {
    // SECURITY: Validate table name against whitelist
    validateTableName(tableName);

    return await this.prisma.$queryRawUnsafe<{name: string; type: string}[]>(`PRAGMA table_info(${tableName})`);
  }

  private async fixColumnNaming(): Promise<void> {
    const migrationName = 'fix_column_naming_snake_case';
    try {
      if (await this.isMigrationApplied(migrationName)) {return;}
      const needsPositionsFix = await this.columnExists('positions', 'userUid');
      const needsReturnsfix = await this.columnExists('hourly_returns', 'userUid');
      const needsTradesFix = await this.columnExists('trades', 'userUid');
      if (needsPositionsFix) {await this.recreatePositionsTable();}
      if (needsReturnsfix) {await this.recreateHourlyReturnsTable();}
      if (needsTradesFix) {await this.recreateTradesTable();}
      await this.markMigrationApplied(migrationName);
    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  private async recreatePositionsTable(): Promise<void> {
    // SECURITY: All table names are hardcoded and validated
    await this.runSequentialQueries([
      'ALTER TABLE positions RENAME TO positions_old;',
      `CREATE TABLE positions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT NOT NULL, exchange TEXT NOT NULL, symbol TEXT NOT NULL, side TEXT CHECK (side IN ('long', 'short')) NOT NULL, size DECIMAL(20,8) NOT NULL, entry_price DECIMAL(20,8), mark_price DECIMAL(20,8), pnl DECIMAL(20,8) DEFAULT 0, realized_pnl DECIMAL(20,8), unrealized_pnl DECIMAL(20,8), percentage DECIMAL(10,4), net_profit DECIMAL(20,8), status TEXT CHECK (status IN ('open', 'closed')) DEFAULT 'open', timestamp TIMESTAMP NOT NULL, closed_at TIMESTAMP DEFAULT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE);`,
      `INSERT INTO positions (user_uid, exchange, symbol, side, size, entry_price, mark_price, pnl, realized_pnl, unrealized_pnl, percentage, net_profit, status, timestamp, closed_at, created_at, updated_at) SELECT userUid, exchange, symbol, side, size, entryPrice, markPrice, pnl, realizedPnl, unrealizedPnl, percentage, netProfit, status, timestamp, NULL as closed_at, created_at, updated_at FROM positions_old;`,
      'CREATE INDEX IF NOT EXISTS idx_positions_user_timestamp ON positions(user_uid, timestamp);',
      'CREATE INDEX IF NOT EXISTS idx_positions_user_exchange ON positions(user_uid, exchange);',
      'CREATE INDEX IF NOT EXISTS idx_positions_status ON positions(status);',
      'DROP TABLE positions_old;'
    ], 'positions');
  }

  private async recreateHourlyReturnsTable(): Promise<void> {
    // SECURITY: All table names are hardcoded and validated
    await this.runSequentialQueries([
      'ALTER TABLE hourly_returns RENAME TO hourly_returns_old;',
      `CREATE TABLE hourly_returns (id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT NOT NULL, hour TEXT NOT NULL, exchange TEXT NOT NULL, volume DECIMAL(20,8) DEFAULT 0, total_quantity DECIMAL(20,8) DEFAULT 0, trades INTEGER DEFAULT 0, return_pct DECIMAL(10,6) DEFAULT 0, return_usd DECIMAL(20,8) DEFAULT 0, total_fees DECIMAL(20,8) DEFAULT 0, realized_pnl DECIMAL(20,8) DEFAULT 0, unrealized_pnl DECIMAL(20,8) DEFAULT 0, matches INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE, UNIQUE(user_uid, hour, exchange));`,
      `INSERT INTO hourly_returns (user_uid, hour, exchange, volume, total_quantity, trades, return_pct, return_usd, total_fees, realized_pnl, unrealized_pnl, matches, created_at, updated_at) SELECT userUid, hour, exchange, volume, totalQuantity, trades, returnPct, returnUsd, totalFees, realizedPnL, unrealizedPnL, matches, created_at, updated_at FROM hourly_returns_old;`,
      'CREATE INDEX IF NOT EXISTS idx_hourly_returns_user_hour ON hourly_returns(user_uid, hour);',
      'DROP TABLE hourly_returns_old;'
    ], 'hourly_returns');
  }

  private async recreateTradesTable(): Promise<void> {
    // SECURITY: All table names are hardcoded and validated
    await this.runSequentialQueries([
      'ALTER TABLE trades RENAME TO trades_old;',
      `CREATE TABLE trades (id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT NOT NULL, exchange TEXT NOT NULL, symbol TEXT NOT NULL, side TEXT CHECK (side IN ('buy', 'sell')) NOT NULL, type TEXT CHECK (type IN ('buy', 'sell')) NOT NULL, quantity DECIMAL(20,8) NOT NULL, price DECIMAL(20,8) NOT NULL, fees DECIMAL(20,8) DEFAULT 0, fee_asset TEXT, timestamp TIMESTAMP NOT NULL, status TEXT CHECK (status IN ('pending', 'matched', 'partially_matched')) DEFAULT 'pending', matched_quantity DECIMAL(20,8) DEFAULT 0, exchange_trade_id TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE);`,
      `INSERT INTO trades (user_uid, exchange, symbol, side, type, quantity, price, fees, fee_asset, timestamp, status, matched_quantity, exchange_trade_id, created_at) SELECT userUid, exchange, symbol, side, side as type, quantity, price, fees, feeAsset, timestamp, 'matched' as status, 0 as matched_quantity, exchangeTradeId, createdAt FROM trades_old;`,
      'CREATE INDEX IF NOT EXISTS idx_trades_user_timestamp ON trades(user_uid, timestamp);',
      'CREATE INDEX IF NOT EXISTS idx_trades_user_exchange ON trades(user_uid, exchange);',
      'DROP TABLE trades_old;'
    ], 'trades');
  }

  /**
   * Execute a list of pre-validated SQL queries sequentially
   * SECURITY: All queries come from hardcoded templates. The tableName is validated.
   */
  private async runSequentialQueries(queries: string[], tableName?: string): Promise<void> {
    // SECURITY: Validate table name if provided
    if (tableName) {
      validateTableName(tableName);
    }

    for (const query of queries) {
      try {
        await this.prisma.$executeRawUnsafe(query);
      }
      catch (err) {
        logger.error(`Error executing query: ${query}`);
        throw err;
      }
    }
  }

  private async fixIdColumnsToAutoIncrement(): Promise<void> {
    const migrationName = 'fix_id_columns_to_autoincrement';
    try {
      if (await this.isMigrationApplied(migrationName)) {return;}
      // SECURITY: All table names are hardcoded from whitelist
      const tables = ['exchange_connections', 'sync_statuses', 'trades', 'positions', 'hourly_returns'];
      for (const tableName of tables) {
        validateTableName(tableName); // Extra validation
        const needsFix = await this.checkIdColumnType(tableName);
        if (needsFix) {await this.recreateTableWithAutoIncrementId(tableName);}
      }
      await this.markMigrationApplied(migrationName);
    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  private async checkIdColumnType(tableName: string): Promise<boolean> {
    // SECURITY: Validate table name against whitelist
    validateTableName(tableName);

    const columns = await this.prisma.$queryRawUnsafe<{name: string; type: string}[]>(`PRAGMA table_info(${tableName})`);
    const idColumn = columns.find(col => col.name === 'id');
    return !idColumn || idColumn.type === 'TEXT';
  }

  private async recreateTableWithAutoIncrementId(tableName: string): Promise<void> {
    // SECURITY: Validate table name against whitelist
    validateTableName(tableName);

    const queries = [
      `ALTER TABLE ${tableName} RENAME TO ${tableName}_old;`,
      this.getAutoIncrementTableSQL(tableName),
      this.getDataCopySQL(tableName),
      ...this.getIndexesSQL(tableName),
      `DROP TABLE ${tableName}_old;`
    ];
    await this.runSequentialQueries(queries, tableName);
  }

  private getAutoIncrementTableSQL(tableName: string): string {
    // SECURITY: Only returns SQL for whitelisted tables
    const tables: Record<string, string> = {
      'exchange_connections': `CREATE TABLE exchange_connections (id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT NOT NULL, exchange TEXT NOT NULL, label TEXT, encrypted_api_key TEXT NOT NULL, encrypted_api_secret TEXT NOT NULL, encrypted_passphrase TEXT, credentials_hash TEXT, is_active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE, UNIQUE(user_uid, exchange, label))`,
      'sync_statuses': `CREATE TABLE sync_statuses (id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT NOT NULL, exchange TEXT NOT NULL, last_sync_time TIMESTAMP, status TEXT CHECK (status IN ('pending', 'running', 'completed', 'error')) DEFAULT 'pending', total_trades INTEGER DEFAULT 0, error_message TEXT, is_historical_complete BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE, UNIQUE(user_uid, exchange))`,
      'trades': `CREATE TABLE trades (id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT NOT NULL, exchange TEXT NOT NULL, symbol TEXT NOT NULL, side TEXT CHECK (side IN ('buy', 'sell')) NOT NULL, type TEXT CHECK (type IN ('buy', 'sell')) NOT NULL, quantity DECIMAL(20,8) NOT NULL, price DECIMAL(20,8) NOT NULL, fees DECIMAL(20,8) DEFAULT 0, fee_asset TEXT, timestamp TIMESTAMP NOT NULL, status TEXT CHECK (status IN ('pending', 'matched', 'partially_matched')) DEFAULT 'pending', matched_quantity DECIMAL(20,8) DEFAULT 0, exchange_trade_id TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE)`,
      'positions': `CREATE TABLE positions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT NOT NULL, exchange TEXT NOT NULL, symbol TEXT NOT NULL, side TEXT CHECK (side IN ('long', 'short')) NOT NULL, size DECIMAL(20,8) NOT NULL, entry_price DECIMAL(20,8), mark_price DECIMAL(20,8), pnl DECIMAL(20,8) DEFAULT 0, realized_pnl DECIMAL(20,8), unrealized_pnl DECIMAL(20,8), percentage DECIMAL(10,4), net_profit DECIMAL(20,8), status TEXT CHECK (status IN ('open', 'closed')) DEFAULT 'open', timestamp TIMESTAMP NOT NULL, closed_at TIMESTAMP DEFAULT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE)`,
      'hourly_returns': `CREATE TABLE hourly_returns (id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT NOT NULL, hour TEXT NOT NULL, exchange TEXT NOT NULL, volume DECIMAL(20,8) DEFAULT 0, total_quantity DECIMAL(20,8) DEFAULT 0, trades INTEGER DEFAULT 0, return_pct DECIMAL(10,6) DEFAULT 0, return_usd DECIMAL(20,8) DEFAULT 0, total_fees DECIMAL(20,8) DEFAULT 0, realized_pnl DECIMAL(20,8) DEFAULT 0, unrealized_pnl DECIMAL(20,8) DEFAULT 0, matches INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE, UNIQUE(user_uid, hour, exchange))`
    };
    if (!tables[tableName]) {throw new Error(`SECURITY: Unknown table "${tableName}" - not in whitelist`);}
    return tables[tableName];
  }

  private getDataCopySQL(tableName: string): string {
    // SECURITY: Only returns SQL for whitelisted tables
    const copies: Record<string, string> = {
      'exchange_connections': `INSERT INTO exchange_connections (user_uid, exchange, label, encrypted_api_key, encrypted_api_secret, encrypted_passphrase, credentials_hash, is_active, created_at, updated_at) SELECT user_uid, exchange, label, encrypted_api_key, encrypted_api_secret, encrypted_passphrase, credentials_hash, is_active, created_at, updated_at FROM exchange_connections_old`,
      'sync_statuses': `INSERT INTO sync_statuses (user_uid, exchange, last_sync_time, status, total_trades, error_message, is_historical_complete, created_at, updated_at) SELECT user_uid, exchange, last_sync_time, status, total_trades, error_message, is_historical_complete, created_at, updated_at FROM sync_statuses_old`,
      'trades': `INSERT INTO trades (user_uid, exchange, symbol, side, type, quantity, price, fees, fee_asset, timestamp, status, matched_quantity, exchange_trade_id, created_at) SELECT user_uid, exchange, symbol, side, type, quantity, price, fees, fee_asset, timestamp, status, matched_quantity, exchange_trade_id, created_at FROM trades_old`,
      'positions': `INSERT INTO positions (user_uid, exchange, symbol, side, size, entry_price, mark_price, pnl, realized_pnl, unrealized_pnl, percentage, net_profit, status, timestamp, closed_at, created_at, updated_at) SELECT user_uid, exchange, symbol, side, size, entry_price, mark_price, pnl, realized_pnl, unrealized_pnl, percentage, net_profit, status, timestamp, closed_at, created_at, updated_at FROM positions_old`,
      'hourly_returns': `INSERT INTO hourly_returns (user_uid, hour, exchange, volume, total_quantity, trades, return_pct, return_usd, total_fees, realized_pnl, unrealized_pnl, matches, created_at, updated_at) SELECT user_uid, hour, exchange, volume, total_quantity, trades, return_pct, return_usd, total_fees, realized_pnl, unrealized_pnl, matches, created_at, updated_at FROM hourly_returns_old`
    };
    if (!copies[tableName]) {throw new Error(`SECURITY: Unknown table "${tableName}" - not in whitelist`);}
    return copies[tableName];
  }

  private getIndexesSQL(tableName: string): string[] {
    // SECURITY: Only returns SQL for whitelisted tables
    const indexes: Record<string, string[]> = {
      'exchange_connections': [],
      'sync_statuses': ['CREATE INDEX IF NOT EXISTS idx_sync_statuses_user_exchange ON sync_statuses(user_uid, exchange);'],
      'trades': ['CREATE INDEX IF NOT EXISTS idx_trades_user_timestamp ON trades(user_uid, timestamp);', 'CREATE INDEX IF NOT EXISTS idx_trades_user_exchange ON trades(user_uid, exchange);'],
      'positions': ['CREATE INDEX IF NOT EXISTS idx_positions_user_timestamp ON positions(user_uid, timestamp);', 'CREATE INDEX IF NOT EXISTS idx_positions_user_exchange ON positions(user_uid, exchange);', 'CREATE INDEX IF NOT EXISTS idx_positions_status ON positions(status);'],
      'hourly_returns': ['CREATE INDEX IF NOT EXISTS idx_hourly_returns_user_hour ON hourly_returns(user_uid, hour);']
    };
    return indexes[tableName] || [];
  }
}
