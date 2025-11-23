import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
import { getLogger } from '../../utils/logger.service';

const logger = getLogger('DatabaseMigrationService');

@injectable()
export class DatabaseMigrationService {
  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  /**
   * Run all necessary migrations to bring the database up to date
   */
  async runMigrations(): Promise<void> {

    try {
      // Check if migrations table exists, create if not
      await this.createMigrationsTable();

      // Run migrations in order
      await this.addCredentialsHashColumn();
      await this.fixColumnNaming();
      await this.addClosedAtColumn();
      await this.addTypeColumnToTrades();
      await this.addStatusColumnToTrades();
      await this.addMatchedQuantityColumnToTrades();
      await this.fixIdColumnsToAutoIncrement();

    } catch (error) {
      logger.error('❌ Database migration failed:', error);
      throw error;
    }
  }

  /**
   * Create migrations table to track applied migrations
   */
  private async createMigrationsTable(): Promise<void> {
    try {
      await this.prisma.$executeRaw`
        CREATE TABLE IF NOT EXISTS migrations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `;
    } catch (err) {
      logger.error('Error creating migrations table:', err);
      throw err;
    }
  }

  /**
   * Check if a migration has already been applied
   */
  private async isMigrationApplied(migrationName: string): Promise<boolean> {
    try {
      const result = await this.prisma.$queryRaw<{count: number}[]>`
        SELECT COUNT(*) as count FROM migrations WHERE name = ${migrationName}
      `;
      return result[0].count > 0;
    } catch (err) {
      throw err;
    }
  }

  /**
   * Mark a migration as applied
   */
  private async markMigrationApplied(migrationName: string): Promise<void> {
    try {
      await this.prisma.$executeRaw`
        INSERT INTO migrations (name) VALUES (${migrationName})
      `;

    } catch (err) {
      throw err;
    }
  }

  /**
   * Add credentials_hash column to exchange_connections table
   */
  private async addCredentialsHashColumn(): Promise<void> {
    const migrationName = 'add_credentials_hash_column';

    try {
      const applied = await this.isMigrationApplied(migrationName);
      if (applied) {

        return;
      }

      // Add the credentials_hash column
      await this.addColumn('exchange_connections', 'credentials_hash', 'TEXT');

      // Mark migration as applied
      await this.markMigrationApplied(migrationName);

    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  /**
   * Add closed_at column to positions table
   */
  private async addClosedAtColumn(): Promise<void> {
    const migrationName = 'add_closed_at_column';

    try {
      const applied = await this.isMigrationApplied(migrationName);
      if (applied) {

        return;
      }

      // Add the closed_at column
      await this.addColumn('positions', 'closed_at', 'TIMESTAMP DEFAULT NULL');

      // Mark migration as applied
      await this.markMigrationApplied(migrationName);

    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  /**
   * Add type column to trades table
   */
  private async addTypeColumnToTrades(): Promise<void> {
    const migrationName = 'add_type_column_to_trades';

    try {
      const applied = await this.isMigrationApplied(migrationName);
      if (applied) {

        return;
      }

      // Add the type column
      await this.addColumn('trades', 'type', 'TEXT CHECK (type IN (\'buy\', \'sell\'))');

      // Populate the type column with the same value as side column
      await this.populateTypeColumn();

      // Mark migration as applied
      await this.markMigrationApplied(migrationName);

    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  /**
   * Populate the type column with side column values
   */
  private async populateTypeColumn(): Promise<void> {
    try {
      const result = await this.prisma.$executeRaw`
        UPDATE trades SET type = side WHERE type IS NULL
      `;

    } catch (err) {
      logger.error('Error populating type column:', err);
      throw err;
    }
  }

  /**
   * Add status column to trades table
   */
  private async addStatusColumnToTrades(): Promise<void> {
    const migrationName = 'add_status_column_to_trades';

    try {
      const applied = await this.isMigrationApplied(migrationName);
      if (applied) {

        return;
      }

      // Add the status column
      await this.addColumn('trades', 'status', 'TEXT CHECK (status IN (\'pending\', \'matched\', \'partially_matched\')) DEFAULT \'pending\'');

      // Populate the status column with default value for existing trades
      await this.populateTradeStatusColumn();

      // Mark migration as applied
      await this.markMigrationApplied(migrationName);

    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  /**
   * Populate the status column with default values
   */
  private async populateTradeStatusColumn(): Promise<void> {
    try {
      const result = await this.prisma.$executeRaw`
        UPDATE trades SET status = 'matched' WHERE status IS NULL
      `;

    } catch (err) {
      logger.error('Error populating trade status column:', err);
      throw err;
    }
  }

  /**
   * Add matched_quantity column to trades table
   */
  private async addMatchedQuantityColumnToTrades(): Promise<void> {
    const migrationName = 'add_matched_quantity_column_to_trades';

    try {
      const applied = await this.isMigrationApplied(migrationName);
      if (applied) {

        return;
      }

      // Add the matched_quantity column
      await this.addColumn('trades', 'matched_quantity', 'DECIMAL(20,8) DEFAULT 0');

      // Mark migration as applied
      await this.markMigrationApplied(migrationName);

    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  /**
   * Helper method to add a column to a table
   */
  private async addColumn(tableName: string, columnName: string, columnType: string): Promise<void> {
    try {
      await this.prisma.$executeRawUnsafe(
        `ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnType}`,
      );

    } catch (err: any) {
      // If column already exists, that's fine
      if (err.message.includes('duplicate column name')) {

      } else {
        logger.error(`Error adding column ${columnName} to ${tableName}`, err);
        throw err;
      }
    }
  }

  /**
   * Check if a column exists in a table
   */
  async columnExists(tableName: string, columnName: string): Promise<boolean> {
    try {
      const rows = await this.prisma.$queryRawUnsafe<any[]>(
        `PRAGMA table_info(${tableName})`,
      );
      const exists = rows.some(row => row.name === columnName);
      return exists;
    } catch (err) {
      throw err;
    }
  }

  /**
   * Get database schema info for debugging
   */
  async getTableInfo(tableName: string): Promise<any[]> {
    try {
      const rows = await this.prisma.$queryRawUnsafe<any[]>(
        `PRAGMA table_info(${tableName})`,
      );
      return rows;
    } catch (err) {
      throw err;
    }
  }

  /**
   * Fix column naming from camelCase to snake_case
   * This migration recreates tables with the correct snake_case column names
   */
  private async fixColumnNaming(): Promise<void> {
    const migrationName = 'fix_column_naming_snake_case';

    try {
      const applied = await this.isMigrationApplied(migrationName);
      if (applied) {

        return;
      }

      // Check if we need to fix the columns by looking for camelCase columns
      const needsPositionsFix = await this.columnExists('positions', 'userUid');
      const needsReturnsfix = await this.columnExists('hourly_returns', 'userUid');
      const needsTradesFix = await this.columnExists('trades', 'userUid');

      if (needsPositionsFix) {
        await this.recreatePositionsTable();
      } else {

      }

      if (needsReturnsfix) {
        await this.recreateHourlyReturnsTable();
      } else {

      }

      if (needsTradesFix) {
        await this.recreateTradesTable();
      } else {

      }

      // Mark migration as applied
      await this.markMigrationApplied(migrationName);

    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  /**
   * Recreate positions table with correct snake_case column names
   */
  private async recreatePositionsTable(): Promise<void> {
    return new Promise((resolve, reject) => {

      const queries = [
        // Rename original table
        'ALTER TABLE positions RENAME TO positions_old;',

        // Create new table with correct snake_case columns
        `CREATE TABLE positions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_uid TEXT NOT NULL,
          exchange TEXT NOT NULL,
          symbol TEXT NOT NULL,
          side TEXT CHECK (side IN ('long', 'short')) NOT NULL,
          size DECIMAL(20,8) NOT NULL,
          entry_price DECIMAL(20,8),
          mark_price DECIMAL(20,8),
          pnl DECIMAL(20,8) DEFAULT 0,
          realized_pnl DECIMAL(20,8),
          unrealized_pnl DECIMAL(20,8),
          percentage DECIMAL(10,4),
          net_profit DECIMAL(20,8),
          status TEXT CHECK (status IN ('open', 'closed')) DEFAULT 'open',
          timestamp TIMESTAMP NOT NULL,
          closed_at TIMESTAMP DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE
        );`,

        // Copy data from old table to new table (excluding id to let it auto-generate)
        `INSERT INTO positions (user_uid, exchange, symbol, side, size, entry_price, mark_price, pnl, realized_pnl, unrealized_pnl, percentage, net_profit, status, timestamp, closed_at, created_at, updated_at)
         SELECT userUid, exchange, symbol, side, size, entryPrice, markPrice, pnl, realizedPnl, unrealizedPnl, percentage, netProfit, status, timestamp, NULL as closed_at, created_at, updated_at
         FROM positions_old;`,

        // Recreate indexes
        'CREATE INDEX IF NOT EXISTS idx_positions_user_timestamp ON positions(user_uid, timestamp);',
        'CREATE INDEX IF NOT EXISTS idx_positions_user_exchange ON positions(user_uid, exchange);',
        'CREATE INDEX IF NOT EXISTS idx_positions_status ON positions(status);',

        // Drop old table
        'DROP TABLE positions_old;',
      ];

      this.runSequentialQueries(queries)
        .then(() => {

          resolve();
        })
        .catch(reject);
    });
  }

  /**
   * Recreate hourly_returns table with correct snake_case column names
   */
  private async recreateHourlyReturnsTable(): Promise<void> {
    return new Promise((resolve, reject) => {

      const queries = [
        // Rename original table
        'ALTER TABLE hourly_returns RENAME TO hourly_returns_old;',

        // Create new table with correct snake_case columns
        `CREATE TABLE hourly_returns (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_uid TEXT NOT NULL,
          hour TEXT NOT NULL,
          exchange TEXT NOT NULL,
          volume DECIMAL(20,8) DEFAULT 0,
          total_quantity DECIMAL(20,8) DEFAULT 0,
          trades INTEGER DEFAULT 0,
          return_pct DECIMAL(10,6) DEFAULT 0,
          return_usd DECIMAL(20,8) DEFAULT 0,
          total_fees DECIMAL(20,8) DEFAULT 0,
          realized_pnl DECIMAL(20,8) DEFAULT 0,
          unrealized_pnl DECIMAL(20,8) DEFAULT 0,
          matches INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE,
          UNIQUE(user_uid, hour, exchange)
        );`,

        // Copy data from old table to new table (excluding id to let it auto-generate)
        `INSERT INTO hourly_returns (user_uid, hour, exchange, volume, total_quantity, trades, return_pct, return_usd, total_fees, realized_pnl, unrealized_pnl, matches, created_at, updated_at)
         SELECT userUid, hour, exchange, volume, totalQuantity, trades, returnPct, returnUsd, totalFees, realizedPnL, unrealizedPnL, matches, created_at, updated_at
         FROM hourly_returns_old;`,

        // Recreate indexes
        'CREATE INDEX IF NOT EXISTS idx_hourly_returns_user_hour ON hourly_returns(user_uid, hour);',

        // Drop old table
        'DROP TABLE hourly_returns_old;',
      ];

      this.runSequentialQueries(queries)
        .then(() => {

          resolve();
        })
        .catch(reject);
    });
  }

  /**
   * Recreate trades table with correct snake_case column names
   */
  private async recreateTradesTable(): Promise<void> {
    return new Promise((resolve, reject) => {

      const queries = [
        // Rename original table
        'ALTER TABLE trades RENAME TO trades_old;',

        // Create new table with correct snake_case columns
        `CREATE TABLE trades (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_uid TEXT NOT NULL,
          exchange TEXT NOT NULL,
          symbol TEXT NOT NULL,
          side TEXT CHECK (side IN ('buy', 'sell')) NOT NULL,
          type TEXT CHECK (type IN ('buy', 'sell')) NOT NULL,
          quantity DECIMAL(20,8) NOT NULL,
          price DECIMAL(20,8) NOT NULL,
          fees DECIMAL(20,8) DEFAULT 0,
          fee_asset TEXT,
          timestamp TIMESTAMP NOT NULL,
          status TEXT CHECK (status IN ('pending', 'matched', 'partially_matched')) DEFAULT 'pending',
          matched_quantity DECIMAL(20,8) DEFAULT 0,
          exchange_trade_id TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE
        );`,

        // Copy data from old table to new table (excluding id to let it auto-generate)
        `INSERT INTO trades (user_uid, exchange, symbol, side, type, quantity, price, fees, fee_asset, timestamp, status, matched_quantity, exchange_trade_id, created_at)
         SELECT userUid, exchange, symbol, side, side as type, quantity, price, fees, feeAsset, timestamp, 'matched' as status, 0 as matched_quantity, exchangeTradeId, createdAt
         FROM trades_old;`,

        // Recreate indexes
        'CREATE INDEX IF NOT EXISTS idx_trades_user_timestamp ON trades(user_uid, timestamp);',
        'CREATE INDEX IF NOT EXISTS idx_trades_user_exchange ON trades(user_uid, exchange);',

        // Drop old table
        'DROP TABLE trades_old;',
      ];

      this.runSequentialQueries(queries)
        .then(() => {

          resolve();
        })
        .catch(reject);
    });
  }

  /**
   * Run a series of SQL queries sequentially
   */
  private async runSequentialQueries(queries: string[]): Promise<void> {
    for (const query of queries) {
      try {
        await this.prisma.$executeRawUnsafe(query);
      } catch (err) {
        logger.error(`Error executing query: ${query}`);
        throw err;
      }
    }
  }

  /**
   * Fix ID columns to use INTEGER PRIMARY KEY AUTOINCREMENT
   * This ensures that this.lastID works properly in repositories
   */
  private async fixIdColumnsToAutoIncrement(): Promise<void> {
    const migrationName = 'fix_id_columns_to_autoincrement';

    try {
      const applied = await this.isMigrationApplied(migrationName);
      if (applied) {

        return;
      }

      // Check if tables need fixing by looking at ID column type
      const tables = ['exchange_connections', 'sync_statuses', 'trades', 'positions', 'hourly_returns'];

      for (const tableName of tables) {
        const needsFix = await this.checkIdColumnType(tableName);
        if (needsFix) {

          await this.recreateTableWithAutoIncrementId(tableName);
        } else {

        }
      }

      // Mark migration as applied
      await this.markMigrationApplied(migrationName);

    } catch (error) {
      logger.error(`Failed to apply migration ${migrationName}:`, error);
      throw error;
    }
  }

  /**
   * Check if a table's ID column is TEXT (needs fixing) or INTEGER (correct)
   */
  private async checkIdColumnType(tableName: string): Promise<boolean> {
    try {
      const columns = await this.prisma.$queryRawUnsafe<any[]>(
        `PRAGMA table_info(${tableName})`,
      );

      const idColumn = columns.find(col => col.name === 'id');
      const needsFix = !idColumn || idColumn.type === 'TEXT';

      return needsFix;
    } catch (err) {
      throw err;
    }
  }

  /**
   * Recreate a table with INTEGER PRIMARY KEY AUTOINCREMENT
   */
  private async recreateTableWithAutoIncrementId(tableName: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const newTableSQL = this.getAutoIncrementTableSQL(tableName);
      const copyDataSQL = this.getDataCopySQL(tableName);
      const indexesSQL = this.getIndexesSQL(tableName);

      const queries = [
        // Rename original table
        `ALTER TABLE ${tableName} RENAME TO ${tableName}_old;`,

        // Create new table with INTEGER PRIMARY KEY AUTOINCREMENT
        newTableSQL,

        // Copy data from old table (excluding id to let it auto-generate)
        copyDataSQL,

        // Recreate indexes
        ...indexesSQL,

        // Drop old table
        `DROP TABLE ${tableName}_old;`,
      ];

      this.runSequentialQueries(queries)
        .then(() => {

          resolve();
        })
        .catch(reject);
    });
  }

  /**
   * Get the CREATE TABLE SQL for a table with INTEGER PRIMARY KEY AUTOINCREMENT
   */
  private getAutoIncrementTableSQL(tableName: string): string {
    switch (tableName) {
      case 'exchange_connections':
        return `
          CREATE TABLE exchange_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT NOT NULL,
            exchange TEXT NOT NULL,
            label TEXT,
            encrypted_api_key TEXT NOT NULL,
            encrypted_api_secret TEXT NOT NULL,
            encrypted_passphrase TEXT,
            credentials_hash TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE,
            UNIQUE(user_uid, exchange, label)
          )
        `;

      case 'sync_statuses':
        return `
          CREATE TABLE sync_statuses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT NOT NULL,
            exchange TEXT NOT NULL,
            last_sync_time TIMESTAMP,
            status TEXT CHECK (status IN ('pending', 'running', 'completed', 'error')) DEFAULT 'pending',
            total_trades INTEGER DEFAULT 0,
            error_message TEXT,
            is_historical_complete BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE,
            UNIQUE(user_uid, exchange)
          )
        `;

      case 'trades':
        return `
          CREATE TABLE trades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT NOT NULL,
            exchange TEXT NOT NULL,
            symbol TEXT NOT NULL,
            side TEXT CHECK (side IN ('buy', 'sell')) NOT NULL,
            type TEXT CHECK (type IN ('buy', 'sell')) NOT NULL,
            quantity DECIMAL(20,8) NOT NULL,
            price DECIMAL(20,8) NOT NULL,
            fees DECIMAL(20,8) DEFAULT 0,
            fee_asset TEXT,
            timestamp TIMESTAMP NOT NULL,
            status TEXT CHECK (status IN ('pending', 'matched', 'partially_matched')) DEFAULT 'pending',
            matched_quantity DECIMAL(20,8) DEFAULT 0,
            exchange_trade_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE
          )
        `;

      case 'positions':
        return `
          CREATE TABLE positions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT NOT NULL,
            exchange TEXT NOT NULL,
            symbol TEXT NOT NULL,
            side TEXT CHECK (side IN ('long', 'short')) NOT NULL,
            size DECIMAL(20,8) NOT NULL,
            entry_price DECIMAL(20,8),
            mark_price DECIMAL(20,8),
            pnl DECIMAL(20,8) DEFAULT 0,
            realized_pnl DECIMAL(20,8),
            unrealized_pnl DECIMAL(20,8),
            percentage DECIMAL(10,4),
            net_profit DECIMAL(20,8),
            status TEXT CHECK (status IN ('open', 'closed')) DEFAULT 'open',
            timestamp TIMESTAMP NOT NULL,
            closed_at TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE
          )
        `;

      case 'hourly_returns':
        return `
          CREATE TABLE hourly_returns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT NOT NULL,
            hour TEXT NOT NULL,
            exchange TEXT NOT NULL,
            volume DECIMAL(20,8) DEFAULT 0,
            total_quantity DECIMAL(20,8) DEFAULT 0,
            trades INTEGER DEFAULT 0,
            return_pct DECIMAL(10,6) DEFAULT 0,
            return_usd DECIMAL(20,8) DEFAULT 0,
            total_fees DECIMAL(20,8) DEFAULT 0,
            realized_pnl DECIMAL(20,8) DEFAULT 0,
            unrealized_pnl DECIMAL(20,8) DEFAULT 0,
            matches INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_uid) REFERENCES users(uid) ON DELETE CASCADE,
            UNIQUE(user_uid, hour, exchange)
          )
        `;

      default:
        throw new Error(`Unknown table: ${tableName}`);
    }
  }

  /**
   * Get the INSERT SQL to copy data without the old ID
   */
  private getDataCopySQL(tableName: string): string {
    switch (tableName) {
      case 'exchange_connections':
        return `
          INSERT INTO exchange_connections (user_uid, exchange, label, encrypted_api_key, encrypted_api_secret, encrypted_passphrase, credentials_hash, is_active, created_at, updated_at)
          SELECT user_uid, exchange, label, encrypted_api_key, encrypted_api_secret, encrypted_passphrase, credentials_hash, is_active, created_at, updated_at
          FROM exchange_connections_old
        `;

      case 'sync_statuses':
        return `
          INSERT INTO sync_statuses (user_uid, exchange, last_sync_time, status, total_trades, error_message, is_historical_complete, created_at, updated_at)
          SELECT user_uid, exchange, last_sync_time, status, total_trades, error_message, is_historical_complete, created_at, updated_at
          FROM sync_statuses_old
        `;

      case 'trades':
        return `
          INSERT INTO trades (user_uid, exchange, symbol, side, type, quantity, price, fees, fee_asset, timestamp, status, matched_quantity, exchange_trade_id, created_at)
          SELECT user_uid, exchange, symbol, side, type, quantity, price, fees, fee_asset, timestamp, status, matched_quantity, exchange_trade_id, created_at
          FROM trades_old
        `;

      case 'positions':
        return `
          INSERT INTO positions (user_uid, exchange, symbol, side, size, entry_price, mark_price, pnl, realized_pnl, unrealized_pnl, percentage, net_profit, status, timestamp, closed_at, created_at, updated_at)
          SELECT user_uid, exchange, symbol, side, size, entry_price, mark_price, pnl, realized_pnl, unrealized_pnl, percentage, net_profit, status, timestamp, closed_at, created_at, updated_at
          FROM positions_old
        `;

      case 'hourly_returns':
        return `
          INSERT INTO hourly_returns (user_uid, hour, exchange, volume, total_quantity, trades, return_pct, return_usd, total_fees, realized_pnl, unrealized_pnl, matches, created_at, updated_at)
          SELECT user_uid, hour, exchange, volume, total_quantity, trades, return_pct, return_usd, total_fees, realized_pnl, unrealized_pnl, matches, created_at, updated_at
          FROM hourly_returns_old
        `;

      default:
        throw new Error(`Unknown table: ${tableName}`);
    }
  }

  /**
   * Get the index creation SQL for a table
   */
  private getIndexesSQL(tableName: string): string[] {
    switch (tableName) {
      case 'exchange_connections':
        return []; // No specific indexes for exchange_connections

      case 'sync_statuses':
        return [
          'CREATE INDEX IF NOT EXISTS idx_sync_statuses_user_exchange ON sync_statuses(user_uid, exchange);',
        ];

      case 'trades':
        return [
          'CREATE INDEX IF NOT EXISTS idx_trades_user_timestamp ON trades(user_uid, timestamp);',
          'CREATE INDEX IF NOT EXISTS idx_trades_user_exchange ON trades(user_uid, exchange);',
        ];

      case 'positions':
        return [
          'CREATE INDEX IF NOT EXISTS idx_positions_user_timestamp ON positions(user_uid, timestamp);',
          'CREATE INDEX IF NOT EXISTS idx_positions_user_exchange ON positions(user_uid, exchange);',
          'CREATE INDEX IF NOT EXISTS idx_positions_status ON positions(status);',
        ];

      case 'hourly_returns':
        return [
          'CREATE INDEX IF NOT EXISTS idx_hourly_returns_user_hour ON hourly_returns(user_uid, hour);',
        ];

      default:
        return [];
    }
  }
}