export const STORAGE_KEYS = {
  PHONE_HISTORY: 'phone_check_history',
  URL_HISTORY: 'url_check_history'
} as const;

export const getStoredHistory = <T>(key: string): T[] => {
  if (typeof window === 'undefined') return [];
  const stored = localStorage.getItem(key);
  return stored ? JSON.parse(stored) : [];
};

export const setStoredHistory = <T>(key: string, items: T[]): void => {
  if (typeof window === 'undefined') return;
  localStorage.setItem(key, JSON.stringify(items));
};

export const addToHistory = <T>(key: string, item: T, maxItems: number = 10): void => {
  const currentHistory = getStoredHistory<T>(key);
  const newHistory = [item, ...currentHistory].slice(0, maxItems);
  setStoredHistory(key, newHistory);
}; 