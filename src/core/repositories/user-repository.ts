import { injectable, inject } from 'tsyringe';
import { PrismaClient } from '@prisma/client';
type PrismaUser = {
  id: string;
  uid: string;
  syncIntervalMinutes: number;
  createdAt: Date;
  updatedAt: Date;
};
import { User, CreateUserRequest } from '../../types';

@injectable()
export class UserRepository {
  constructor(
    @inject('PrismaClient') private readonly prisma: PrismaClient,
  ) {}

  /**
   * Crée un nouvel utilisateur (ou retourne l'existant si déjà présent)
   */
  async createUser(userData: CreateUserRequest): Promise<User> {
    const createdUser = await this.prisma.user.upsert({
      where: {
        uid: userData.uid,
      },
      update: {},
      create: {
        uid: userData.uid,
      },
    });

    return this.mapPrismaUserToUser(createdUser);
  }

  /**
   * Récupère un utilisateur par UID
   */
  async getUserByUid(uid: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({
      where: { uid },
    });

    return user ? this.mapPrismaUserToUser(user) : null;
  }

  /**
   * Récupère un utilisateur par ID
   */
  async getUserById(id: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    return user ? this.mapPrismaUserToUser(user) : null;
  }

  /**
   * Met à jour les informations d'un utilisateur
   */
  async updateUser(uid: string, updateData: Partial<Pick<User, 'syncIntervalMinutes' | 'createdAt' | 'updatedAt'>>): Promise<User> {
    const updatedUser = await this.prisma.user.update({
      where: { uid },
      data: updateData,
    });

    return this.mapPrismaUserToUser(updatedUser);
  }

  /**
   * Supprime un utilisateur
   */
  async deleteUser(uid: string): Promise<void> {
    await this.prisma.user.delete({
      where: { uid },
    });
  }

  /**
   * Vérifie si un utilisateur existe
   */
  async userExists(uid: string): Promise<boolean> {
    const count = await this.prisma.user.count({
      where: { uid },
    });

    return count > 0;
  }

  /**
   * Récupère tous les utilisateurs (pour admin)
   */
  async getAllUsers(): Promise<User[]> {
    const users = await this.prisma.user.findMany({
      orderBy: { createdAt: 'desc' },
    });

    return users.map(this.mapPrismaUserToUser);
  }

  /**
   * Compte le nombre total d'utilisateurs
   */
  async countUsers(): Promise<number> {
    return this.prisma.user.count();
  }

  /**
   * Récupère les statistiques d'un utilisateur
   */
  async getUserStats(uid: string): Promise<{
    totalTrades: number;
    totalPositions: number;
    exchangeConnections: number;
    accountAge: number; // en jours
  }> {
    const user = await this.prisma.user.findUnique({
      where: { uid },
      include: {
        _count: {
          select: {
            trades: true,
            positions: true,
            exchangeConnections: true,
          },
        },
      },
    });

    if (!user) {
      throw new Error(`User with UID ${uid} not found`);
    }

    const accountAge = Math.floor(
      (Date.now() - user.createdAt.getTime()) / (1000 * 60 * 60 * 24),
    );

    return {
      totalTrades: user._count.trades,
      totalPositions: user._count.positions,
      exchangeConnections: user._count.exchangeConnections,
      accountAge,
    };
  }

  /**
   * Mappe un utilisateur Prisma vers le type User de l'application
   */
  private mapPrismaUserToUser(prismaUser: PrismaUser): User {
    return {
      id: prismaUser.id,
      uid: prismaUser.uid,
      syncIntervalMinutes: prismaUser.syncIntervalMinutes,
      createdAt: prismaUser.createdAt,
      updatedAt: prismaUser.updatedAt,
    };
  }
}