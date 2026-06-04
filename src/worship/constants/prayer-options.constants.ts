import { CalculationMethod, Madhab } from 'adhan';

export type CalculationMethodKey = keyof typeof CalculationMethod;
export type MadhabKey = keyof typeof Madhab;
export type MadhabValue = (typeof Madhab)[MadhabKey];

export const DEFAULT_CALCULATION_METHOD: CalculationMethodKey = 'Turkey';
export const DEFAULT_MADHAB: MadhabKey = 'Shafi';

export interface CalculationMethodOption {
  key: CalculationMethodKey;
  isDefault: boolean;
}

export interface MadhabOption {
  key: MadhabKey;
  value: MadhabValue;
  isDefault: boolean;
}

function calculationMethodKeys(): CalculationMethodKey[] {
  return (Object.keys(CalculationMethod) as CalculationMethodKey[]).filter(
    (k) => typeof CalculationMethod[k] === 'function',
  );
}

function madhabKeys(): MadhabKey[] {
  return Object.keys(Madhab) as MadhabKey[];
}

export function normalizeCalculationMethod(input: unknown): CalculationMethodKey | null {
  if (typeof input !== 'string') return null;
  const lowered = input.trim().toLowerCase();
  if (!lowered) return null;
  return calculationMethodKeys().find((k) => k.toLowerCase() === lowered) ?? null;
}

export function normalizeMadhab(input: unknown): MadhabKey | null {
  if (typeof input !== 'string') return null;
  const lowered = input.trim().toLowerCase();
  if (!lowered) return null;
  return madhabKeys().find((k) => k.toLowerCase() === lowered || Madhab[k] === lowered) ?? null;
}

export function resolveAdhanSelection(
  rawMethod: unknown,
  rawMadhab: unknown,
): { method: CalculationMethodKey; madhab: MadhabKey } {
  return {
    method: normalizeCalculationMethod(rawMethod) ?? DEFAULT_CALCULATION_METHOD,
    madhab: normalizeMadhab(rawMadhab) ?? DEFAULT_MADHAB,
  };
}
