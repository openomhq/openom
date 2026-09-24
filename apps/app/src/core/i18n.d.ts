export interface LocaleInfo {
  readonly id: string;
  readonly label: string;
  readonly dir: 'ltr' | 'rtl';
  readonly script: string;
}

export const LOCALES: readonly LocaleInfo[];
export function localeInfo(id?: string): LocaleInfo;
export function detectLocale(): string;
export function persistLocale(id: string): void;
export function isRTL(): boolean;
export function loadLocale(id: string): Promise<string>;
export function locale(): string;
export function t(key: string, args?: Readonly<Record<string, unknown>>): string;
export function dateSymbols(): { birth: string; death: string; marriage: string };
