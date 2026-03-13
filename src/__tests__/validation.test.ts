import { describe, expect, it } from 'vitest';
import { DATE_RE, DAYS_IN_MONTH, isLeapYear, isValidDate } from '../validation.js';

describe('DATE_RE', () => {
  it('matches a well-formed YYYY-MM-DD string', () => {
    expect(DATE_RE.test('2026-03-13')).toBe(true);
  });

  it('rejects a string with wrong separators', () => {
    expect(DATE_RE.test('2026/03/13')).toBe(false);
  });

  it('rejects a string with too few digits in year', () => {
    expect(DATE_RE.test('26-03-13')).toBe(false);
  });

  it('rejects a string with single-digit month', () => {
    expect(DATE_RE.test('2026-3-13')).toBe(false);
  });

  it('rejects a string with single-digit day', () => {
    expect(DATE_RE.test('2026-03-1')).toBe(false);
  });

  it('rejects an empty string', () => {
    expect(DATE_RE.test('')).toBe(false);
  });

  it('rejects a string with extra characters', () => {
    expect(DATE_RE.test('2026-03-13T00:00')).toBe(false);
  });

  it('rejects a string with leading space', () => {
    expect(DATE_RE.test(' 2026-03-13')).toBe(false);
  });
});

describe('DAYS_IN_MONTH', () => {
  it('has 12 entries', () => {
    expect(DAYS_IN_MONTH).toHaveLength(12);
  });

  it('has 31 for January (index 0)', () => {
    expect(DAYS_IN_MONTH[0]).toBe(31);
  });

  it('has 28 for February (index 1) as the non-leap default', () => {
    expect(DAYS_IN_MONTH[1]).toBe(28);
  });

  it('has 30 for April (index 3)', () => {
    expect(DAYS_IN_MONTH[3]).toBe(30);
  });

  it('has 31 for December (index 11)', () => {
    expect(DAYS_IN_MONTH[11]).toBe(31);
  });
});

describe('isLeapYear', () => {
  it('returns true for a year divisible by 4 but not 100', () => {
    expect(isLeapYear(2024)).toBe(true);
  });

  it('returns false for a year divisible by 100 but not 400', () => {
    expect(isLeapYear(1900)).toBe(false);
  });

  it('returns true for a year divisible by 400', () => {
    expect(isLeapYear(2000)).toBe(true);
  });

  it('returns false for an odd year', () => {
    expect(isLeapYear(2023)).toBe(false);
  });

  it('returns false for a year divisible by 2 but not 4', () => {
    expect(isLeapYear(2025)).toBe(false);
  });
});

describe('isValidDate', () => {
  it('accepts a normal valid date', () => {
    expect(isValidDate('2026-03-13')).toBe(true);
  });

  it('accepts January 1 of year 0001', () => {
    expect(isValidDate('0001-01-01')).toBe(true);
  });

  it('accepts the last day of each month in a non-leap year', () => {
    const lastDays = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (let m = 1; m <= 12; m++) {
      const month = String(m).padStart(2, '0');
      const day = String(lastDays[m - 1]).padStart(2, '0');
      expect(isValidDate(`2023-${month}-${day}`)).toBe(true);
    }
  });

  it('accepts Feb 29 in a leap year', () => {
    expect(isValidDate('2024-02-29')).toBe(true);
  });

  it('rejects Feb 29 in a non-leap year', () => {
    expect(isValidDate('2023-02-29')).toBe(false);
  });

  it('rejects Feb 29 in a century non-leap year', () => {
    expect(isValidDate('1900-02-29')).toBe(false);
  });

  it('accepts Feb 29 in a 400-year leap year', () => {
    expect(isValidDate('2000-02-29')).toBe(true);
  });

  it('rejects month 0', () => {
    expect(isValidDate('2026-00-15')).toBe(false);
  });

  it('rejects month 13', () => {
    expect(isValidDate('2026-13-15')).toBe(false);
  });

  it('rejects day 0', () => {
    expect(isValidDate('2026-03-00')).toBe(false);
  });

  it('rejects day 32 in a 31-day month', () => {
    expect(isValidDate('2026-01-32')).toBe(false);
  });

  it('rejects day 31 in a 30-day month', () => {
    expect(isValidDate('2026-04-31')).toBe(false);
  });

  it('rejects year 0000', () => {
    expect(isValidDate('0000-01-01')).toBe(false);
  });

  it('rejects a non-date string that passes the regex', () => {
    // This would pass DATE_RE but fails calendar checks
    expect(isValidDate('9999-12-32')).toBe(false);
  });

  it('rejects a string with wrong format', () => {
    expect(isValidDate('not-a-date')).toBe(false);
  });

  it('rejects an empty string', () => {
    expect(isValidDate('')).toBe(false);
  });

  it('rejects a date with extra suffix', () => {
    expect(isValidDate('2026-03-13T00:00:00Z')).toBe(false);
  });
});
