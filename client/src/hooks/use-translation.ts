import { useContext } from 'react';
import { LanguageContext } from '@/lib/i18n';

/**
 * Custom hook to access translations
 */
export function useTranslation() {
  const context = useContext(LanguageContext);
  
  if (!context) {
    throw new Error('useTranslation must be used within a LanguageProvider');
  }
  
  const { language, translations, setLanguage } = context;
  
  /**
   * Translate a key to the current language
   * @param key The translation key
   * @param defaultValue Default value to use if the key is not found
   * @param params Optional parameters to replace in the translation
   */
  const t = (key: string, defaultValue: string, params?: Record<string, string | number>): string => {
    // Get the translation for the current language
    const translation = translations[language]?.[key] || defaultValue;

    // Replace parameters in the translation if provided
    if (params) {
      return Object.entries(params).reduce((result, [param, value]) => {
        return result.replace(new RegExp(`{${param}}`, 'g'), String(value));
      }, translation);
    }

    return translation;
  };

  return {
    t,
    language,
    setLanguage,
  };
}