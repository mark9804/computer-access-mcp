import en from '../../locale/en.json' with { type: 'json' };
import zh from '../../locale/zh.json' with { type: 'json' };

export type Language = 'zh' | 'en';
export type MessageKey = keyof typeof en.ui;
export type Translate = (key: MessageKey) => string;

const dictionaries: Record<Language, Record<MessageKey, string>> = {
  en: en.ui,
  zh: zh.ui,
};

export function initialLanguage(): Language {
  try {
    const saved = localStorage.getItem('camcp_lang');
    if (saved === 'zh' || saved === 'en') return saved;
  } catch {
    // Ignore storage failures in restricted contexts.
  }
  return typeof navigator !== 'undefined' && navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en';
}

export function persistLanguage(lang: Language): void {
  try {
    localStorage.setItem('camcp_lang', lang);
  } catch {
    // Ignore storage failures.
  }
}

export function createTranslator(lang: Language): Translate {
  const dict = dictionaries[lang];
  return (key: MessageKey) => dict[key];
}
