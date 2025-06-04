export const STORAGE_KEYS = {
  PHONE_HISTORY: 'phone_check_history',
  URL_HISTORY: 'url_check_history'
} as const;

export function getStoredHistory<T>(key: string): T[] {
  try {
    const stored = localStorage.getItem(key);
    return stored ? JSON.parse(stored) : [];
  } catch (e) {
    console.error(`Error reading ${key} from localStorage:`, e);
    return [];
  }
}

export function addToHistory<T>(key: string, item: T): void {
  try {
    const current = getStoredHistory<T>(key);
    const updated = [item, ...current].slice(0, 10); // Keep only last 10 items
    localStorage.setItem(key, JSON.stringify(updated));
  } catch (e) {
    console.error(`Error updating ${key} in localStorage:`, e);
  }
}

export function clearHistory(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch (e) {
    console.error(`Error clearing ${key} from localStorage:`, e);
  }
} 