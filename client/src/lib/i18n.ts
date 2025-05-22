/**
 * Simple internationalization (i18n) utility for the application
 */

// Define the available languages
export const AVAILABLE_LANGUAGES = {
  en: 'English',
  fr: 'Français',
  es: 'Español',
  de: 'Deutsch',
  zh: '中文',
  ja: '日本語',
  id: 'Bahasa Indonesia'
};

// Define the language translations
export type TranslationKeys =
  | 'whois.title'
  | 'whois.subtitle'
  | 'whois.domain.label'
  | 'whois.domain.placeholder'
  | 'whois.domain.hint'
  | 'whois.button.lookup'
  | 'whois.button.loading'
  | 'whois.error.empty'
  | 'whois.error.invalid'
  | 'whois.loading'
  | 'whois.result.age'
  | 'whois.result.domainInfo'
  | 'whois.result.registrar'
  | 'whois.result.registrarUrl'
  | 'whois.result.status'
  | 'whois.result.dates'
  | 'whois.result.creationDate'
  | 'whois.result.expiryDate'
  | 'whois.result.lastUpdated'
  | 'whois.result.registrantInfo'
  | 'whois.result.organization'
  | 'whois.result.name'
  | 'whois.result.email'
  | 'whois.result.country'
  | 'whois.result.nameServers'
  | 'whois.note'
  | 'whois.about.title'
  | 'whois.about.description'
  | 'whois.privacy.title'
  | 'whois.privacy.description';

// Define the translations
export const translations: Record<string, Record<TranslationKeys, string>> = {
  en: {
    'whois.title': 'WHOIS Domain Lookup',
    'whois.subtitle': 'Discover who owns a domain, when it was registered, and when it expires. Our WHOIS lookup tool provides comprehensive registration data for any domain.',
    'whois.domain.label': 'Domain Name',
    'whois.domain.placeholder': 'example.com',
    'whois.domain.hint': 'Enter a domain name without \'http://\' or \'www\'. Example: example.com',
    'whois.button.lookup': 'Lookup',
    'whois.button.loading': 'Loading...',
    'whois.error.empty': 'Please enter a domain name',
    'whois.error.invalid': 'Invalid domain format. Example: example.com',
    'whois.loading': 'Retrieving WHOIS information for {domain}...',
    'whois.result.age': '{years} years old',
    'whois.result.domainInfo': 'Domain Information',
    'whois.result.registrar': 'Registrar',
    'whois.result.registrarUrl': 'Registrar URL',
    'whois.result.status': 'Status',
    'whois.result.dates': 'Important Dates',
    'whois.result.creationDate': 'Creation Date',
    'whois.result.expiryDate': 'Expiry Date',
    'whois.result.lastUpdated': 'Last Updated',
    'whois.result.registrantInfo': 'Registrant Information',
    'whois.result.organization': 'Organization',
    'whois.result.name': 'Name',
    'whois.result.email': 'Email',
    'whois.result.country': 'Country',
    'whois.result.nameServers': 'Name Servers',
    'whois.note': 'Note: WHOIS data may be masked or limited due to privacy protection services.',
    'whois.about.title': 'About WHOIS Lookup',
    'whois.about.description': 'WHOIS (pronounced as "who is") is a query and response protocol that is widely used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block, or an autonomous system. This tool helps you find information about domain names, including the registrar, registration date, and contact information.',
    'whois.privacy.title': 'Privacy Notice',
    'whois.privacy.description': 'Please note that some domain registrars may implement privacy protection services that hide the actual owner\'s details from public WHOIS queries. In such cases, you might see the registrar\'s information or a privacy service instead of the actual owner\'s details.'
  },
  fr: {
    'whois.title': 'Recherche de Domaine WHOIS',
    'whois.subtitle': 'Découvrez qui possède un domaine, quand il a été enregistré et quand il expire. Notre outil de recherche WHOIS fournit des données d\'enregistrement complètes pour n\'importe quel domaine.',
    'whois.domain.label': 'Nom de Domaine',
    'whois.domain.placeholder': 'exemple.com',
    'whois.domain.hint': 'Entrez un nom de domaine sans \'http://\' ou \'www\'. Exemple: exemple.com',
    'whois.button.lookup': 'Rechercher',
    'whois.button.loading': 'Chargement...',
    'whois.error.empty': 'Veuillez entrer un nom de domaine',
    'whois.error.invalid': 'Format de domaine invalide. Exemple: exemple.com',
    'whois.loading': 'Récupération des informations WHOIS pour {domain}...',
    'whois.result.age': '{years} ans',
    'whois.result.domainInfo': 'Informations sur le Domaine',
    'whois.result.registrar': 'Bureau d\'Enregistrement',
    'whois.result.registrarUrl': 'URL du Bureau d\'Enregistrement',
    'whois.result.status': 'Statut',
    'whois.result.dates': 'Dates Importantes',
    'whois.result.creationDate': 'Date de Création',
    'whois.result.expiryDate': 'Date d\'Expiration',
    'whois.result.lastUpdated': 'Dernière Mise à Jour',
    'whois.result.registrantInfo': 'Informations sur le Titulaire',
    'whois.result.organization': 'Organisation',
    'whois.result.name': 'Nom',
    'whois.result.email': 'Email',
    'whois.result.country': 'Pays',
    'whois.result.nameServers': 'Serveurs de Noms',
    'whois.note': 'Remarque: Les données WHOIS peuvent être masquées ou limitées en raison des services de protection de la vie privée.',
    'whois.about.title': 'À Propos de la Recherche WHOIS',
    'whois.about.description': 'WHOIS (prononcé "qui est") est un protocole de requête et de réponse largement utilisé pour interroger les bases de données qui stockent les utilisateurs ou les titulaires enregistrés d\'une ressource Internet, comme un nom de domaine, un bloc d\'adresses IP, ou un système autonome. Cet outil vous aide à trouver des informations sur les noms de domaine, y compris le bureau d\'enregistrement, la date d\'enregistrement et les coordonnées.',
    'whois.privacy.title': 'Avis de Confidentialité',
    'whois.privacy.description': 'Veuillez noter que certains bureaux d\'enregistrement de domaines peuvent implémenter des services de protection de la vie privée qui masquent les détails du propriétaire réel des requêtes WHOIS publiques. Dans de tels cas, vous pourriez voir les informations du bureau d\'enregistrement ou d\'un service de confidentialité au lieu des détails du propriétaire réel.'
  },
  es: {
    'whois.title': 'Búsqueda de Dominio WHOIS',
    'whois.subtitle': 'Descubra quién es el propietario de un dominio, cuándo se registró y cuándo expira. Nuestra herramienta de búsqueda WHOIS proporciona datos completos de registro para cualquier dominio.',
    'whois.domain.label': 'Nombre de Dominio',
    'whois.domain.placeholder': 'ejemplo.com',
    'whois.domain.hint': 'Introduzca un nombre de dominio sin \'http://\' o \'www\'. Ejemplo: ejemplo.com',
    'whois.button.lookup': 'Buscar',
    'whois.button.loading': 'Cargando...',
    'whois.error.empty': 'Por favor, introduzca un nombre de dominio',
    'whois.error.invalid': 'Formato de dominio no válido. Ejemplo: ejemplo.com',
    'whois.loading': 'Recuperando información WHOIS para {domain}...',
    'whois.result.age': '{years} años',
    'whois.result.domainInfo': 'Información del Dominio',
    'whois.result.registrar': 'Registrador',
    'whois.result.registrarUrl': 'URL del Registrador',
    'whois.result.status': 'Estado',
    'whois.result.dates': 'Fechas Importantes',
    'whois.result.creationDate': 'Fecha de Creación',
    'whois.result.expiryDate': 'Fecha de Expiración',
    'whois.result.lastUpdated': 'Última Actualización',
    'whois.result.registrantInfo': 'Información del Registrante',
    'whois.result.organization': 'Organización',
    'whois.result.name': 'Nombre',
    'whois.result.email': 'Correo Electrónico',
    'whois.result.country': 'País',
    'whois.result.nameServers': 'Servidores de Nombres',
    'whois.note': 'Nota: Los datos de WHOIS pueden estar enmascarados o limitados debido a servicios de protección de privacidad.',
    'whois.about.title': 'Acerca de la Búsqueda WHOIS',
    'whois.about.description': 'WHOIS (pronunciado como "quién es") es un protocolo de consulta y respuesta ampliamente utilizado para consultar bases de datos que almacenan los usuarios registrados o cesionarios de un recurso de Internet, como un nombre de dominio, un bloque de direcciones IP o un sistema autónomo. Esta herramienta le ayuda a encontrar información sobre nombres de dominio, incluido el registrador, la fecha de registro y la información de contacto.',
    'whois.privacy.title': 'Aviso de Privacidad',
    'whois.privacy.description': 'Tenga en cuenta que algunos registradores de dominios pueden implementar servicios de protección de privacidad que ocultan los detalles del propietario real de las consultas WHOIS públicas. En tales casos, es posible que vea la información del registrador o un servicio de privacidad en lugar de los detalles del propietario real.'
  },
  de: {
    'whois.title': 'WHOIS Domain-Abfrage',
    'whois.subtitle': 'Entdecken Sie, wem eine Domain gehört, wann sie registriert wurde und wann sie abläuft. Unser WHOIS-Lookup-Tool bietet umfassende Registrierungsdaten für jede Domain.',
    'whois.domain.label': 'Domainname',
    'whois.domain.placeholder': 'beispiel.com',
    'whois.domain.hint': 'Geben Sie einen Domainnamen ohne \'http://\' oder \'www\' ein. Beispiel: beispiel.com',
    'whois.button.lookup': 'Abfragen',
    'whois.button.loading': 'Lädt...',
    'whois.error.empty': 'Bitte geben Sie einen Domainnamen ein',
    'whois.error.invalid': 'Ungültiges Domain-Format. Beispiel: beispiel.com',
    'whois.loading': 'WHOIS-Informationen für {domain} werden abgerufen...',
    'whois.result.age': '{years} Jahre alt',
    'whois.result.domainInfo': 'Domain-Informationen',
    'whois.result.registrar': 'Registrar',
    'whois.result.registrarUrl': 'Registrar-URL',
    'whois.result.status': 'Status',
    'whois.result.dates': 'Wichtige Daten',
    'whois.result.creationDate': 'Erstellungsdatum',
    'whois.result.expiryDate': 'Ablaufdatum',
    'whois.result.lastUpdated': 'Zuletzt aktualisiert',
    'whois.result.registrantInfo': 'Registrant-Informationen',
    'whois.result.organization': 'Organisation',
    'whois.result.name': 'Name',
    'whois.result.email': 'E-Mail',
    'whois.result.country': 'Land',
    'whois.result.nameServers': 'Nameserver',
    'whois.note': 'Hinweis: WHOIS-Daten können aufgrund von Datenschutzdiensten maskiert oder eingeschränkt sein.',
    'whois.about.title': 'Über WHOIS-Lookup',
    'whois.about.description': 'WHOIS (ausgesprochen als "wer ist") ist ein Abfrage- und Antwortprotokoll, das häufig verwendet wird, um Datenbanken abzufragen, die die registrierten Benutzer oder Inhaber einer Internetressource speichern, wie z.B. einen Domainnamen, einen IP-Adressblock oder ein autonomes System. Dieses Tool hilft Ihnen, Informationen über Domainnamen zu finden, einschließlich des Registrars, des Registrierungsdatums und der Kontaktinformationen.',
    'whois.privacy.title': 'Datenschutzhinweis',
    'whois.privacy.description': 'Bitte beachten Sie, dass einige Domain-Registrare Datenschutzdienste implementieren können, die die Details des tatsächlichen Eigentümers vor öffentlichen WHOIS-Abfragen verbergen. In solchen Fällen sehen Sie möglicherweise die Informationen des Registrars oder eines Datenschutzdienstes anstelle der Details des tatsächlichen Eigentümers.'
  },
  zh: {
    'whois.title': 'WHOIS 域名查询',
    'whois.subtitle': '了解域名的所有者、注册时间以及到期时间。我们的 WHOIS 查询工具为任何域名提供全面的注册数据。',
    'whois.domain.label': '域名',
    'whois.domain.placeholder': 'example.com',
    'whois.domain.hint': '请输入不含 \'http://\' 或 \'www\' 的域名。例如: example.com',
    'whois.button.lookup': '查询',
    'whois.button.loading': '加载中...',
    'whois.error.empty': '请输入域名',
    'whois.error.invalid': '域名格式无效。例如: example.com',
    'whois.loading': '正在获取 {domain} 的 WHOIS 信息...',
    'whois.result.age': '{years} 年历史',
    'whois.result.domainInfo': '域名信息',
    'whois.result.registrar': '注册商',
    'whois.result.registrarUrl': '注册商网址',
    'whois.result.status': '状态',
    'whois.result.dates': '重要日期',
    'whois.result.creationDate': '创建日期',
    'whois.result.expiryDate': '到期日期',
    'whois.result.lastUpdated': '最后更新',
    'whois.result.registrantInfo': '注册人信息',
    'whois.result.organization': '组织',
    'whois.result.name': '姓名',
    'whois.result.email': '电子邮件',
    'whois.result.country': '国家',
    'whois.result.nameServers': '名称服务器',
    'whois.note': '注意: 由于隐私保护服务，WHOIS 数据可能被屏蔽或受限。',
    'whois.about.title': '关于 WHOIS 查询',
    'whois.about.description': 'WHOIS (发音为 "who is") 是一种广泛用于查询存储互联网资源注册用户或受让人的数据库的查询和响应协议，例如域名、IP 地址块或自治系统。此工具可帮助您查找有关域名的信息，包括注册商、注册日期和联系信息。',
    'whois.privacy.title': '隐私声明',
    'whois.privacy.description': '请注意，某些域名注册商可能会实施隐私保护服务，以将实际所有者的详细信息从公共 WHOIS 查询中隐藏。在这种情况下，您可能会看到注册商的信息或隐私服务，而不是实际所有者的详细信息。'
  },
  ja: {
    'whois.title': 'WHOIS ドメイン検索',
    'whois.subtitle': 'ドメインの所有者、登録日、有効期限を調べます。当社の WHOIS 検索ツールは、あらゆるドメインの包括的な登録データを提供します。',
    'whois.domain.label': 'ドメイン名',
    'whois.domain.placeholder': 'example.com',
    'whois.domain.hint': '\'http://\' や \'www\' を含まないドメイン名を入力してください。例: example.com',
    'whois.button.lookup': '検索',
    'whois.button.loading': '読み込み中...',
    'whois.error.empty': 'ドメイン名を入力してください',
    'whois.error.invalid': 'ドメイン形式が無効です。例: example.com',
    'whois.loading': '{domain} の WHOIS 情報を取得しています...',
    'whois.result.age': '{years} 年前',
    'whois.result.domainInfo': 'ドメイン情報',
    'whois.result.registrar': 'レジストラ',
    'whois.result.registrarUrl': 'レジストラ URL',
    'whois.result.status': 'ステータス',
    'whois.result.dates': '重要な日付',
    'whois.result.creationDate': '作成日',
    'whois.result.expiryDate': '有効期限',
    'whois.result.lastUpdated': '最終更新日',
    'whois.result.registrantInfo': '登録者情報',
    'whois.result.organization': '組織',
    'whois.result.name': '名前',
    'whois.result.email': 'メール',
    'whois.result.country': '国',
    'whois.result.nameServers': 'ネームサーバー',
    'whois.note': '注意: WHOIS データはプライバシー保護サービスのため、マスクされたり制限されたりする場合があります。',
    'whois.about.title': 'WHOIS 検索について',
    'whois.about.description': 'WHOIS（「フーイズ」と発音）は、ドメイン名、IP アドレスブロック、自律システムなどのインターネットリソースの登録ユーザーや譲受人を保存するデータベースを照会するために広く使用されている照会および応答プロトコルです。このツールは、レジストラ、登録日、連絡先情報など、ドメイン名に関する情報を見つけるのに役立ちます。',
    'whois.privacy.title': 'プライバシーに関する注意',
    'whois.privacy.description': '一部のドメインレジストラは、実際の所有者の詳細を公開 WHOIS クエリから隠すプライバシー保護サービスを実装している場合があることにご注意ください。このような場合、実際の所有者の詳細ではなく、レジストラの情報またはプライバシーサービスが表示される場合があります。'
  },
  id: {
    'whois.title': 'Pencarian Domain WHOIS',
    'whois.subtitle': 'Temukan siapa pemilik domain, kapan didaftarkan, dan kapan kedaluwarsa. Alat pencarian WHOIS kami menyediakan data pendaftaran lengkap untuk domain apa pun.',
    'whois.domain.label': 'Nama Domain',
    'whois.domain.placeholder': 'contoh.com',
    'whois.domain.hint': 'Masukkan nama domain tanpa \'http://\' atau \'www\'. Contoh: contoh.com',
    'whois.button.lookup': 'Cari',
    'whois.button.loading': 'Memuat...',
    'whois.error.empty': 'Silakan masukkan nama domain',
    'whois.error.invalid': 'Format domain tidak valid. Contoh: contoh.com',
    'whois.loading': 'Mengambil informasi WHOIS untuk {domain}...',
    'whois.result.age': '{years} tahun',
    'whois.result.domainInfo': 'Informasi Domain',
    'whois.result.registrar': 'Registrar',
    'whois.result.registrarUrl': 'URL Registrar',
    'whois.result.status': 'Status',
    'whois.result.dates': 'Tanggal Penting',
    'whois.result.creationDate': 'Tanggal Pembuatan',
    'whois.result.expiryDate': 'Tanggal Kedaluwarsa',
    'whois.result.lastUpdated': 'Terakhir Diperbarui',
    'whois.result.registrantInfo': 'Informasi Pendaftar',
    'whois.result.organization': 'Organisasi',
    'whois.result.name': 'Nama',
    'whois.result.email': 'Email',
    'whois.result.country': 'Negara',
    'whois.result.nameServers': 'Server Nama',
    'whois.note': 'Catatan: Data WHOIS mungkin disamarkan atau dibatasi karena layanan perlindungan privasi.',
    'whois.about.title': 'Tentang Pencarian WHOIS',
    'whois.about.description': 'WHOIS (diucapkan sebagai "who is") adalah protokol kueri dan respons yang banyak digunakan untuk menanyakan database yang menyimpan pengguna terdaftar atau penerima dari sumber daya Internet, seperti nama domain, blok alamat IP, atau sistem otonom. Alat ini membantu Anda menemukan informasi tentang nama domain, termasuk registrar, tanggal pendaftaran, dan informasi kontak.',
    'whois.privacy.title': 'Pemberitahuan Privasi',
    'whois.privacy.description': 'Harap dicatat bahwa beberapa registrar domain mungkin menerapkan layanan perlindungan privasi yang menyembunyikan detail pemilik sebenarnya dari kueri WHOIS publik. Dalam kasus seperti itu, Anda mungkin melihat informasi registrar atau layanan privasi alih-alih detail pemilik sebenarnya.'
  }
};

/**
 * Create and manage a language context
 */
export function createI18n() {
  // Get the language from local storage or use the browser language or default to English
  const getInitialLanguage = (): string => {
    const storedLang = localStorage.getItem('language');
    if (storedLang && Object.keys(translations).includes(storedLang)) {
      return storedLang;
    }

    const browserLang = navigator.language.split('-')[0];
    if (Object.keys(translations).includes(browserLang)) {
      return browserLang;
    }

    return 'en';
  };

  // Initialize the language
  let currentLanguage = getInitialLanguage();

  // Function to get a translation
  const t = (key: TranslationKeys, replacements?: Record<string, string | number>): string => {
    // Get the translation
    const translation = translations[currentLanguage]?.[key] || translations.en[key] || key;

    // Replace any placeholders
    if (replacements) {
      return Object.keys(replacements).reduce((str, placeholder) => {
        return str.replace(`{${placeholder}}`, String(replacements[placeholder]));
      }, translation);
    }

    return translation;
  };

  // Function to change the language
  const setLanguage = (lang: string): void => {
    if (Object.keys(translations).includes(lang)) {
      currentLanguage = lang;
      localStorage.setItem('language', lang);
      // Trigger a custom event to notify components that the language has changed
      window.dispatchEvent(new CustomEvent('languagechange', { detail: { language: lang } }));
    }
  };

  // Function to get the current language
  const getLanguage = (): string => {
    return currentLanguage;
  };

  return {
    t,
    setLanguage,
    getLanguage
  };
}

// Create a singleton instance
export const i18n = createI18n();