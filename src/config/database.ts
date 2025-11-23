import { PrismaClient } from '@prisma/client';
import { getPrismaClient } from './prisma';

export class DatabaseService {
  private static instance: PrismaClient | null = null;

  static getInstance(): PrismaClient {
    if (!DatabaseService.instance) {
      DatabaseService.instance = getPrismaClient();
    }
    return DatabaseService.instance;
  }

  static async disconnect(): Promise<void> {
    if (DatabaseService.instance) {
      await DatabaseService.instance.$disconnect();
      DatabaseService.instance = null;
    }
  }
}