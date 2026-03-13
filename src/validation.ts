/**
 * Shared date validation utilities.
 *
 * Calendar-correct date parsing without relying on the Date constructor
 * (which silently rolls invalid dates like Feb 30 → Mar 2).
 */

export const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
export const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

export function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

export function isValidDate(value: string): boolean {
  if (!DATE_RE.test(value)) return false;

  const year = parseInt(value.slice(0, 4), 10);
  const month = parseInt(value.slice(5, 7), 10);
  const day = parseInt(value.slice(8, 10), 10);

  if (year < 1) return false;
  if (month < 1 || month > 12) return false;

  let maxDay = DAYS_IN_MONTH[month - 1];
  if (month === 2 && isLeapYear(year)) maxDay = 29;

  return day >= 1 && day <= maxDay;
}
