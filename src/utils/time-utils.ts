export class TimeUtils {
  /**
   * Tronque une date à l'heure (supprime les minutes, secondes, millisecondes)
   * Exemple: '2024-01-15T14:23:45.123Z' -> '2024-01-15T14:00:00.000Z'
   */
  static truncateToHour(date: Date): Date {
    const truncated = new Date(date);
    truncated.setMinutes(0, 0, 0);
    return truncated;
  }

  /**
   * Formate une date en string ISO tronquée à l'heure
   */
  static formatHour(date: Date): string {
    return this.truncateToHour(date).toISOString();
  }

  /**
   * Parse une string d'heure et la retourne comme Date tronquée à l'heure
   */
  static parseHour(hourString: string): Date {
    const date = new Date(hourString);
    return this.truncateToHour(date);
  }

  /**
   * Génère une liste d'heures entre startHour et endHour
   */
  static generateHourRange(startHour: Date, endHour: Date): Date[] {
    const hours: Date[] = [];
    const current = this.truncateToHour(startHour);
    const end = this.truncateToHour(endHour);

    while (current <= end) {
      hours.push(new Date(current));
      current.setHours(current.getHours() + 1);
    }

    return hours;
  }

  /**
   * Retourne l'heure de début de la période (ex: début de la journée pour aggregation daily)
   */
  static getPeriodStart(date: Date, aggregation: 'hourly' | 'daily' | 'weekly' | 'monthly'): Date {
    const result = new Date(date);

    switch (aggregation) {
      case 'hourly':
        return this.truncateToHour(result);

      case 'daily':
        result.setHours(0, 0, 0, 0);
        return result;

      case 'weekly': {
        const day = result.getDay();
        const diff = result.getDate() - day + (day === 0 ? -6 : 1); // Lundi = début de semaine
        result.setDate(diff);
        result.setHours(0, 0, 0, 0);
        return result;
      }

      case 'monthly':
        result.setDate(1);
        result.setHours(0, 0, 0, 0);
        return result;

      default:
        return this.truncateToHour(result);
    }
  }

  /**
   * Retourne l'heure de fin de la période
   */
  static getPeriodEnd(date: Date, aggregation: 'hourly' | 'daily' | 'weekly' | 'monthly'): Date {
    const result = new Date(date);

    switch (aggregation) {
      case 'hourly': {
        const hourEnd = this.truncateToHour(result);
        hourEnd.setHours(hourEnd.getHours() + 1);
        hourEnd.setMilliseconds(-1); // 59:59:59.999
        return hourEnd;
      }

      case 'daily':
        result.setHours(23, 59, 59, 999);
        return result;

      case 'weekly': {
        const startOfWeek = this.getPeriodStart(date, 'weekly');
        const endOfWeek = new Date(startOfWeek);
        endOfWeek.setDate(endOfWeek.getDate() + 6);
        endOfWeek.setHours(23, 59, 59, 999);
        return endOfWeek;
      }

      case 'monthly':
        result.setMonth(result.getMonth() + 1, 0); // Dernier jour du mois
        result.setHours(23, 59, 59, 999);
        return result;

      default: {
        const defaultEnd = this.truncateToHour(result);
        defaultEnd.setHours(defaultEnd.getHours() + 1);
        defaultEnd.setMilliseconds(-1);
        return defaultEnd;
      }
    }
  }

  /**
   * Vérifie si une date est dans une heure spécifique
   */
  static isInHour(date: Date, hour: Date): boolean {
    const truncatedDate = this.truncateToHour(date);
    const truncatedHour = this.truncateToHour(hour);
    return truncatedDate.getTime() === truncatedHour.getTime();
  }
}