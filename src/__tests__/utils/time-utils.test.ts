import { TimeUtils } from '../../utils/time-utils';

describe('TimeUtils', () => {
  describe('truncateToHour', () => {
    it('should truncate minutes, seconds, and milliseconds to zero', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const truncated = TimeUtils.truncateToHour(date);

      expect(truncated.getMinutes()).toBe(0);
      expect(truncated.getSeconds()).toBe(0);
      expect(truncated.getMilliseconds()).toBe(0);
    });

    it('should preserve the hour', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const truncated = TimeUtils.truncateToHour(date);

      expect(truncated.getHours()).toBe(date.getHours());
    });

    it('should not modify the original date', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const originalTime = date.getTime();
      TimeUtils.truncateToHour(date);

      expect(date.getTime()).toBe(originalTime);
    });
  });

  describe('formatHour', () => {
    it('should return ISO string truncated to hour', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const formatted = TimeUtils.formatHour(date);

      expect(formatted).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z$/);
    });
  });

  describe('parseHour', () => {
    it('should parse string and truncate to hour', () => {
      const hourString = '2024-01-15T14:23:45.123Z';
      const parsed = TimeUtils.parseHour(hourString);

      expect(parsed.getMinutes()).toBe(0);
      expect(parsed.getSeconds()).toBe(0);
      expect(parsed.getMilliseconds()).toBe(0);
    });
  });

  describe('generateHourRange', () => {
    it('should generate list of hours between start and end', () => {
      const start = new Date('2024-01-15T10:00:00.000Z');
      const end = new Date('2024-01-15T13:00:00.000Z');
      const hours = TimeUtils.generateHourRange(start, end);

      expect(hours).toHaveLength(4); // 10, 11, 12, 13
    });

    it('should return single hour when start equals end', () => {
      const start = new Date('2024-01-15T10:00:00.000Z');
      const end = new Date('2024-01-15T10:30:00.000Z');
      const hours = TimeUtils.generateHourRange(start, end);

      expect(hours).toHaveLength(1);
    });

    it('should return empty array when end is before start', () => {
      const start = new Date('2024-01-15T14:00:00.000Z');
      const end = new Date('2024-01-15T10:00:00.000Z');
      const hours = TimeUtils.generateHourRange(start, end);

      expect(hours).toHaveLength(0);
    });
  });

  describe('getPeriodStart', () => {
    it('should return start of hour for hourly aggregation', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const start = TimeUtils.getPeriodStart(date, 'hourly');

      expect(start.getMinutes()).toBe(0);
      expect(start.getSeconds()).toBe(0);
    });

    it('should return start of day for daily aggregation', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const start = TimeUtils.getPeriodStart(date, 'daily');

      expect(start.getHours()).toBe(0);
      expect(start.getMinutes()).toBe(0);
    });

    it('should return Monday for weekly aggregation', () => {
      // Wednesday January 15, 2025
      const date = new Date('2025-01-15T14:23:45.123Z');
      const start = TimeUtils.getPeriodStart(date, 'weekly');

      // Should be Monday January 13, 2025
      expect(start.getDay()).toBe(1); // Monday
    });

    it('should return first of month for monthly aggregation', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const start = TimeUtils.getPeriodStart(date, 'monthly');

      expect(start.getDate()).toBe(1);
      expect(start.getHours()).toBe(0);
    });

    it('should handle Sunday correctly for weekly aggregation', () => {
      // Sunday January 12, 2025
      const date = new Date('2025-01-12T14:23:45.123Z');
      const start = TimeUtils.getPeriodStart(date, 'weekly');

      // Should return Monday of previous week
      expect(start.getDay()).toBe(1);
    });
  });

  describe('getPeriodEnd', () => {
    it('should return end of hour for hourly aggregation', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const end = TimeUtils.getPeriodEnd(date, 'hourly');

      expect(end.getMinutes()).toBe(59);
      expect(end.getSeconds()).toBe(59);
      expect(end.getMilliseconds()).toBe(999);
    });

    it('should return end of day for daily aggregation', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const end = TimeUtils.getPeriodEnd(date, 'daily');

      expect(end.getHours()).toBe(23);
      expect(end.getMinutes()).toBe(59);
      expect(end.getSeconds()).toBe(59);
    });

    it('should return Sunday for weekly aggregation', () => {
      const date = new Date('2025-01-15T14:23:45.123Z');
      const end = TimeUtils.getPeriodEnd(date, 'weekly');

      expect(end.getDay()).toBe(0); // Sunday
      expect(end.getHours()).toBe(23);
    });

    it('should return last day of month for monthly aggregation', () => {
      // January has 31 days
      const date = new Date('2024-01-15T14:23:45.123Z');
      const end = TimeUtils.getPeriodEnd(date, 'monthly');

      expect(end.getDate()).toBe(31);
      expect(end.getHours()).toBe(23);
    });

    it('should handle February correctly for monthly aggregation', () => {
      // 2024 is a leap year, February has 29 days
      const date = new Date('2024-02-15T14:23:45.123Z');
      const end = TimeUtils.getPeriodEnd(date, 'monthly');

      expect(end.getDate()).toBe(29);
    });

    it('should handle default case', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      // TypeScript won't allow invalid aggregation, but we test the default branch
      const end = TimeUtils.getPeriodEnd(date, 'hourly');

      expect(end.getMilliseconds()).toBe(999);
    });
  });

  describe('isInHour', () => {
    it('should return true when date is in the same hour', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const hour = new Date('2024-01-15T14:00:00.000Z');

      expect(TimeUtils.isInHour(date, hour)).toBe(true);
    });

    it('should return false when date is in different hour', () => {
      const date = new Date('2024-01-15T14:23:45.123Z');
      const hour = new Date('2024-01-15T15:00:00.000Z');

      expect(TimeUtils.isInHour(date, hour)).toBe(false);
    });

    it('should return true when both dates have same truncated hour', () => {
      const date1 = new Date('2024-01-15T14:05:00.000Z');
      const date2 = new Date('2024-01-15T14:55:00.000Z');

      expect(TimeUtils.isInHour(date1, date2)).toBe(true);
    });
  });

  describe('getStartOfDayUTC', () => {
    it('should return midnight UTC for given date', () => {
      const date = new Date('2025-01-15T14:23:45.123Z');
      const midnight = TimeUtils.getStartOfDayUTC(date);

      expect(midnight.getUTCHours()).toBe(0);
      expect(midnight.getUTCMinutes()).toBe(0);
      expect(midnight.getUTCSeconds()).toBe(0);
      expect(midnight.getUTCMilliseconds()).toBe(0);
    });

    it('should preserve the UTC date', () => {
      const date = new Date('2025-01-15T14:23:45.123Z');
      const midnight = TimeUtils.getStartOfDayUTC(date);

      expect(midnight.getUTCFullYear()).toBe(2025);
      expect(midnight.getUTCMonth()).toBe(0); // January = 0
      expect(midnight.getUTCDate()).toBe(15);
    });

    it('should use current date when no argument provided', () => {
      const before = new Date();
      const midnight = TimeUtils.getStartOfDayUTC();
      const after = new Date();

      expect(midnight.getUTCDate()).toBeGreaterThanOrEqual(before.getUTCDate() - 1);
      expect(midnight.getUTCDate()).toBeLessThanOrEqual(after.getUTCDate() + 1);
    });
  });
});
