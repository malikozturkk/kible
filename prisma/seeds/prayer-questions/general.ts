import { SeedPrayerQuestion } from '../seed-types';

export const GENERAL_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Namazın farzlarından biri olan, namaza başlarken alınan tekbirin adı nedir?',
    explanation:
      'Namaza başlarken alınan "Allahu ekber" tekbirine iftitah (başlangıç) tekbiri denir ve namazın farzlarındandır.',
    difficulty: 1,
    options: [
      { text: 'İntikal tekbiri', isCorrect: false },
      { text: 'Zevâid tekbiri', isCorrect: false },
      { text: 'Teşrik tekbiri', isCorrect: false },
      { text: 'İftitah tekbiri', isCorrect: true },
    ],
  },
  {
    prompt: 'Günde kaç vakit namaz farzdır?',
    explanation:
      'Sabah, öğle, ikindi, akşam ve yatsı olmak üzere günde beş vakit namaz farzdır. Cuma günü öğlenin yerine Cuma namazı kılınır.',
    difficulty: 1,
    options: [
      { text: '7 vakit', isCorrect: false },
      { text: '6 vakit', isCorrect: false },
      { text: '5 vakit', isCorrect: true },
      { text: '3 vakit', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazın şartlarından olan, bedenin ve elbisenin temiz olması neye denir?',
    explanation:
      'Bedenin, elbisenin ve namaz kılınan yerin necâsetten temiz olmasına "necâsetten tahâret" denir ve namazın dış şartlarındandır.',
    difficulty: 2,
    options: [
      { text: 'Vakit', isCorrect: false },
      { text: 'Setr-i avret', isCorrect: false },
      { text: 'Necâsetten tahâret', isCorrect: true },
      { text: 'İstikbâl-i kıble', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazda kıbleye yönelmenin adı nedir?',
    explanation:
      'Kâbe yönüne dönmeye "istikbâl-i kıble" denir ve namazın şartlarındandır. Yön tespit edilemezse araştırılıp kanaate göre yönelinir.',
    difficulty: 2,
    options: [
      { text: 'İstikbâl-i kıble', isCorrect: true },
      { text: 'Hadesten tahâret', isCorrect: false },
      { text: "Ta'dîl-i erkân", isCorrect: false },
      { text: 'Setr-i avret', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazda her rekatta okunması gereken sure hangisidir?',
    explanation:
      'Fatiha suresi her rekatta okunur. Hanefîlerde Fatiha okumak vacip, kıraatin aslı ise farzdır.',
    difficulty: 1,
    options: [
      { text: 'Fatiha suresi', isCorrect: true },
      { text: 'İhlâs suresi', isCorrect: false },
      { text: 'Nas suresi', isCorrect: false },
      { text: 'Kevser suresi', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazda eğilerek elleri dizlere koymaya ne denir?',
    explanation:
      'Kıraatten sonra belin eğilip ellerin dizlere konulduğu duruşa rükû denir ve namazın farzlarındandır.',
    difficulty: 1,
    options: [
      { text: "Ka'de", isCorrect: false },
      { text: 'Kıyam', isCorrect: false },
      { text: 'Rükû', isCorrect: true },
      { text: 'Secde', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazda alnı, burnu, elleri, dizleri ve ayak parmaklarını yere koymaya ne denir?',
    explanation:
      'Bu duruşa secde denir ve her rekatta iki defa yapılır. Secde namazın farzlarındandır.',
    difficulty: 1,
    options: [
      { text: 'Teşehhüd', isCorrect: false },
      { text: 'Secde', isCorrect: true },
      { text: 'Kıyam', isCorrect: false },
      { text: 'Rükû', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazda ayakta durmaya ne ad verilir?',
    explanation:
      'Namazda ayakta durmaya kıyam denir ve farz namazlarda özürsüz terkedilemez. Nafilelerde oturarak kılmak câizdir.',
    difficulty: 1,
    options: [
      { text: 'Kıyam', isCorrect: true },
      { text: "Ka'de", isCorrect: false },
      { text: 'Rükû', isCorrect: false },
      { text: 'Celse', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazın son oturuşunda okunan duaya ne denir?',
    explanation:
      'Son oturuşta okunan "Ettehiyyâtü..." duasına Tahiyyât (teşehhüd) denir. Ardından salavat ve dua okunup selâm verilir.',
    difficulty: 1,
    options: [
      { text: 'Kunut', isCorrect: false },
      { text: 'Tahiyyât (teşehhüd)', isCorrect: true },
      { text: 'Tesbihat', isCorrect: false },
      { text: 'Sübhâneke', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazı bitirirken sağa ve sola dönerek verilen selâmın adı nedir?',
    explanation:
      'Namazın sonunda sağa ve sola dönerek "es-selâmü aleyküm ve rahmetullah" denmesine selâm denir ve namazdan çıkışı ifade eder.',
    difficulty: 1,
    options: [
      { text: 'Selâm', isCorrect: true },
      { text: 'Kunut', isCorrect: false },
      { text: 'İftitah', isCorrect: false },
      { text: 'Kamet', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazda yanılma sebebiyle yapılan iki secdeye ne denir?',
    explanation:
      'Namazın vaciplerinden biri yanılarak terkedildiğinde veya geciktirildiğinde son oturuşta selâmdan sonra yapılan iki secdeye sehiv secdesi denir.',
    difficulty: 2,
    options: [
      { text: 'Küsûf secdesi', isCorrect: false },
      { text: 'Tilâvet secdesi', isCorrect: false },
      { text: 'Sehiv secdesi', isCorrect: true },
      { text: 'Şükür secdesi', isCorrect: false },
    ],
  },
  {
    prompt: 'Abdesti bozan durumlardan biri aşağıdakilerden hangisidir?',
    explanation:
      "Uykuya dalmak, bayılmak, ön veya arka yoldan bir şey çıkması abdesti bozar. Kur'an okumak veya konuşmak abdesti bozmaz.",
    difficulty: 2,
    options: [
      { text: 'Derin uykuya dalmak', isCorrect: true },
      { text: 'Kıbleye sırtını dönmek', isCorrect: false },
      { text: "Sesli Kur'an okumak", isCorrect: false },
      { text: 'Ayakta su içmek', isCorrect: false },
    ],
  },
  {
    prompt: 'Namaz kılarken vücudun örtülmesi gereken bölgelerine ne denir?',
    explanation:
      'Namazda örtülmesi farz olan bölgelere avret mahalli denir; bunun örtülmesine "setr-i avret" adı verilir ve namazın şartlarındandır.',
    difficulty: 2,
    options: [
      { text: 'Kıble mahalli', isCorrect: false },
      { text: 'Avret mahalli', isCorrect: true },
      { text: 'Mihrap', isCorrect: false },
      { text: 'Musallâ', isCorrect: false },
    ],
  },
  {
    prompt: 'Cemaatle namazda öndeki safları tamamlamanın hükmü nedir?',
    explanation:
      'Safların düzgün ve boşluksuz tutulması, önce ön safların doldurulması sünnettir. Hz. Peygamber safların düzeltilmesine özellikle dikkat çekmiştir.',
    difficulty: 2,
    options: [
      { text: 'Yalnızca Cuma günü geçerlidir', isCorrect: false },
      { text: 'Farzdır; aksi hâlde namaz geçersizdir', isCorrect: false },
      { text: 'Mekruhtur; arka saflar tercih edilir', isCorrect: false },
      { text: 'Sünnettir; saflar boşluksuz tutulur', isCorrect: true },
    ],
  },
  {
    prompt: 'Namazı vaktinden sonra kılmaya ne denir?',
    explanation:
      'Vakti çıktıktan sonra kılınan namaza kaza namazı denir. Vakti içinde kılınana ise edâ denir.',
    difficulty: 1,
    options: [
      { text: 'Edâ', isCorrect: false },
      { text: 'Kaza', isCorrect: true },
      { text: 'Nafile', isCorrect: false },
      { text: 'İâde', isCorrect: false },
    ],
  },
  {
    prompt: 'Namazda rükû ve secdeleri acele etmeden, düzgün şekilde yapmaya ne denir?',
    explanation:
      'Rükû, secde ve doğrulmaların âzâlar yerine oturacak şekilde sükûnetle yapılmasına "ta\'dîl-i erkân" denir.',
    difficulty: 3,
    options: [
      { text: 'İstikbâl-i kıble', isCorrect: false },
      { text: 'Hadesten tahâret', isCorrect: false },
      { text: 'Setr-i avret', isCorrect: false },
      { text: "Ta'dîl-i erkân", isCorrect: true },
    ],
  },
  {
    prompt: 'Namaza çağrı için okunan duyuruya ne ad verilir?',
    explanation:
      'Namaz vaktinin girdiğini bildiren çağrıya ezan denir. Namaza durulmadan hemen önce okunana ise kamet adı verilir.',
    difficulty: 1,
    options: [
      { text: 'Salâ', isCorrect: false },
      { text: 'Tesbihat', isCorrect: false },
      { text: 'Hutbe', isCorrect: false },
      { text: 'Ezan', isCorrect: true },
    ],
  },
  {
    prompt: 'Abdestsiz kişinin namaz kılması hakkında hüküm nedir?',
    explanation:
      'Abdest namazın şartlarındandır. Abdestsiz kılınan namaz geçerli olmaz; abdest alınıp yeniden kılınması gerekir.',
    difficulty: 1,
    options: [
      { text: 'Sehiv secdesiyle geçerli hâle gelir', isCorrect: false },
      { text: 'Namazı geçerlidir, sevabı azalır', isCorrect: false },
      { text: 'Yalnızca nafilelerde geçersizdir', isCorrect: false },
      { text: 'Namazı geçerli olmaz, yeniden kılar', isCorrect: true },
    ],
  },
  {
    prompt: 'Namazda kasten konuşmak namazı nasıl etkiler?',
    explanation:
      'Namazda kasten konuşmak namazı bozar. Namaz yeniden kılınmalıdır; sehiv secdesi bu durumu düzeltmez.',
    difficulty: 2,
    options: [
      { text: 'Sehiv secdesiyle telâfi edilir', isCorrect: false },
      { text: 'Namazı bozar, yeniden kılınır', isCorrect: true },
      { text: 'Namaza hiçbir etkisi olmaz', isCorrect: false },
      { text: 'Yalnızca sevabını azaltır', isCorrect: false },
    ],
  },
  {
    prompt: 'Farz namazlardan sonra yapılan zikir ve duaya ne denir?',
    explanation:
      "Farz namazların ardından yapılan tesbih, tahmid ve tekbirlerle duaya tesbihat denir. Âyetü'l-Kürsî okumak da bu zikrin bir parçasıdır.",
    difficulty: 1,
    options: [
      { text: 'Kunut', isCorrect: false },
      { text: 'Kamet', isCorrect: false },
      { text: 'Tesbihat', isCorrect: true },
      { text: 'Hutbe', isCorrect: false },
    ],
  },
];
