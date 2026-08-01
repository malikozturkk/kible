import { SeedPrayerQuestion } from '../seed-types';

export const ASR_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'İkindi namazının farzı kaç rekattır?',
    explanation:
      'İkindinin farzı 4 rekat olup sirrî olarak kılınır. Öncesindeki 4 rekat sünnet gayri müekkeddir; ikindi farzından sonra sünnet kılınmaz.',
    difficulty: 1,
    options: [
      { text: '2 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: true },
      { text: '6 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindi namazından sonra kaç rekat sünnet kılınır?',
    explanation:
      'İkindi farzından sonra sünnet kılınmaz. Bu vakit, güneş batıncaya kadar nafile namaz için mekruh sayılır.',
    difficulty: 2,
    options: [
      { text: '2 rekat', isCorrect: false },
      { text: '6 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
      { text: 'Sünnet kılınmaz', isCorrect: true },
    ],
  },
  {
    prompt: 'İkindi namazının kıraati nasıl yapılır?',
    explanation:
      'İkindi namazı sirrî (sessiz) namazlardandır. Cemaatle de münferid de Fatiha ve zammı sure içten okunur.',
    difficulty: 1,
    options: [
      { text: 'Sesli (cehrî)', isCorrect: false },
      { text: 'Sadece ilk rekatta sesli', isCorrect: false },
      { text: 'Sessiz (sirrî)', isCorrect: true },
      { text: 'İmam sesli, cemaat sessiz', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindi vakti, öğle vakti çıktıktan sonra başlar ve ne zaman sona erer?',
    explanation: 'İkindi vakti, öğle vaktinin çıkışıyla başlar ve güneş batıncaya kadar sürer.',
    difficulty: 1,
    options: [
      { text: 'Güneşin tepeye ulaşmasına kadar', isCorrect: false },
      { text: 'Güneş batıncaya kadar', isCorrect: true },
      { text: 'Yatsı vakti girene kadar', isCorrect: false },
      { text: 'Fecre kadar', isCorrect: false },
    ],
  },
  {
    prompt:
      'Güneşin batmaya yaklaştığı, ışığının zayıflayıp sararıp kızarmaya başladığı vakitte ikindiyi kılmak nasıldır?',
    explanation:
      'Bu vakte "ısfirar" denir ve mekruh vakittir. İkindiyi kasıtlı olarak bu vakte bırakmak doğru değildir; o günün ikindisini bu vakitte ancak iade etmeden kılan kişinin namazı sahihtir fakat tahrîmen mekruh olur.',
    difficulty: 3,
    options: [
      { text: 'Mekruhtur, ancak o günün ikindisi sahih kılınmış olur', isCorrect: true },
      { text: 'Tamamen geçersizdir', isCorrect: false },
      { text: 'Müstehaptır', isCorrect: false },
      { text: 'Vacip kılan vakittir', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindi vakti girmeden kılınan "ikindi" namazı geçerli olur mu?',
    explanation:
      'Vakit girmeden farz namaz sahih olmaz. Vakitten önce kılınan ikindi farzı geçersizdir; vakit girince iade edilmesi gerekir.',
    difficulty: 2,
    options: [
      { text: 'Geçerlidir; sevap eksilir', isCorrect: false },
      { text: 'Sadece cemaatle geçerlidir', isCorrect: false },
      { text: 'Geçersizdir; iade edilmelidir', isCorrect: true },
      { text: 'Niyet doğruysa geçerlidir', isCorrect: false },
    ],
  },
  {
    prompt: 'Hanefîlerde ikindinin sünneti müekked midir?',
    explanation:
      'İkindinin ilk 4 rekat sünneti gayri müekkeddir. Hz. Peygamberin devamlı kıldığı sünnetlerden olmadığı için terki günah değildir, ancak kılınması faziletlidir.',
    difficulty: 2,
    options: [
      { text: 'Gayri müekked sünnettir', isCorrect: true },
      { text: 'Vaciptir', isCorrect: false },
      { text: 'Müekked sünnettir', isCorrect: false },
      { text: "Bid'attir", isCorrect: false },
    ],
  },
  {
    prompt:
      'Bir kimse ikindi farzına 1. rekatın rükûunda yetişirse o rekatı imamla birlikte kılmış sayılır mı?',
    explanation:
      'İmama rükûda yetişen kişi o rekata yetişmiş sayılır. Bu, ikindi de dahil tüm namazlarda geçerli olan genel bir kuraldır.',
    difficulty: 3,
    options: [
      { text: 'Sadece imamla birlikte selâm verene yetişmiş sayılır', isCorrect: false },
      { text: 'Evet; rükûya yetişen rekata yetişmiştir', isCorrect: true },
      { text: 'Sadece tekbir alıp Fatiha okuyana yetişen sayılır', isCorrect: false },
      { text: 'Hayır; sadece kıyâma yetişen sayılır', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindiden sonra cenaze namazı kılınabilir mi?',
    explanation:
      'İkindi sonrasında, güneşin ısfirar vakti dışında, cenaze namazı kılınabilir. Cenaze namazı vakti müsait olduğu sürece kerâhet vakitleri dışında geciktirilmez.',
    difficulty: 3,
    options: [
      { text: 'Sadece imamlı ise kılınır', isCorrect: false },
      { text: 'Sadece kadınlar kılar', isCorrect: false },
      { text: 'Hiçbir şekilde kılınamaz', isCorrect: false },
      { text: 'Kerâhet vakti dışında kılınabilir', isCorrect: true },
    ],
  },
  {
    prompt:
      "\"Salâtu'l-vustâ\" (orta namaz) Kur'an'da hangi namaz için kullanılmıştır (yaygın görüş)?",
    explanation:
      'Bakara 238. ayette geçen "salâtu\'l-vustâ" hakkında en kuvvetli rivayet ikindi namazına işaret ettiği yönündedir. Hz. Peygamber Hendek günü "salâtu\'l-vustâ olan ikindi"den söz etmiştir.',
    difficulty: 3,
    options: [
      { text: 'Öğle (zuhr) namazı', isCorrect: false },
      { text: 'Akşam namazı', isCorrect: false },
      { text: 'Vitir namazı', isCorrect: false },
      { text: 'İkindi (asr) namazı', isCorrect: true },
    ],
  },
  {
    prompt:
      'İkindi farzında ilk iki rekattan sonra Tahiyyât için oturulur; bu oturuş namazın hangi unsurudur?',
    explanation:
      'Dört rekatlı farzlardaki ara oturuş "kâde-i ûlâ"dır ve vaciptir. Burada yalnız Tahiyyât okunur; unutularak terki sehiv secdesini gerektirir.',
    difficulty: 3,
    options: [
      { text: 'Vacip olan kâde-i ûlâ', isCorrect: true },
      { text: 'Müstehap olan kâde-i ûlâ', isCorrect: false },
      { text: 'Mubah bir oturuştur', isCorrect: false },
      { text: 'Farz olan kâde-i ahîre', isCorrect: false },
    ],
  },
  {
    prompt: 'Vakti içinde ikindiyi kılamayıp güneş batan kişinin durumu nedir?',
    explanation:
      'Vakit çıktıktan sonra namaz kazaya kalır. Sahibi, kazasını kerâhet vakitlerinin dışında ilk fırsatta eda eder; tertip sahibi ise sıraya riayet eder.',
    difficulty: 2,
    options: [
      { text: 'Düşer; sorumluluğu kalkar', isCorrect: false },
      { text: 'Kaza eder', isCorrect: true },
      { text: 'Sadece sünneti kaza eder', isCorrect: false },
      { text: 'Yatsı ile birleştirir', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindi namazından sonra hangi vakit kerâhet vakti sayılır?',
    explanation:
      'İkindiyi kıldıktan sonra güneş batmaya yaklaşıp sararmaya başladığı andan batışa kadar olan süre kerâhet vaktidir; bu vakitte nafile kılınmaz.',
    difficulty: 2,
    options: [
      { text: 'Akşam ezanından sonraki ilk saat', isCorrect: false },
      { text: 'Güneşin tam tepede olduğu kısa süre', isCorrect: false },
      { text: 'İkindi ezanından hemen sonraki yarım saat', isCorrect: false },
      { text: 'Güneşin sararmasından batışına kadar olan süre', isCorrect: true },
    ],
  },
  {
    prompt: 'Seferî olan kişi ikindi namazının farzını kaç rekat kılar?',
    explanation:
      'Yolculukta dört rekatlı farzlar iki rekat olarak kısaltılır. İkindinin farzı da seferî için iki rekat kılınır.',
    difficulty: 1,
    options: [
      { text: '6 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
      { text: '2 rekat', isCorrect: true },
      { text: '3 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindi namazını cemaatle kılmak için hangi şart aranır?',
    explanation:
      'Cemaat için imamın dışında en az bir kişinin bulunması yeterlidir. Belirli bir sayı veya mescit şartı yoktur.',
    difficulty: 2,
    options: [
      { text: 'İmamın resmî görevli olması', isCorrect: false },
      { text: 'En az kırk kişinin bulunması', isCorrect: false },
      { text: 'İmamdan başka en az bir kişinin bulunması', isCorrect: true },
      { text: 'Namazın mutlaka camide kılınması', isCorrect: false },
    ],
  },
  {
    prompt: "İkindi namazında imama uyan kişi Fatiha'yı kendisi okur mu (Hanefî)?",
    explanation:
      'Hanefîlere göre imamın kıraati cemaatin de kıraati sayılır. Cemaat sessiz namazlarda da Fatiha okumaz, sessizce dinler ve imamı takip eder.',
    difficulty: 3,
    options: [
      { text: 'Evet, ancak sadece son iki rekatta okur', isCorrect: false },
      { text: 'Evet, her rekatta yüksek sesle okur', isCorrect: false },
      { text: 'Hayır, imamın kıraati cemaate de yeterlidir', isCorrect: true },
      { text: 'Evet, sadece ilk rekatta okur', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindi namazının farzını kılarken abdesti bozulan kişi ne yapar?',
    explanation:
      'Abdest namazın şartlarındandır; bozulduğunda namaz sona erer. Kişi abdestini yenileyip namaza yeniden başlar.',
    difficulty: 2,
    options: [
      { text: 'Namazı kaldığı yerden sürdürür', isCorrect: false },
      { text: 'Abdestini yenileyip namaza yeniden başlar', isCorrect: true },
      { text: 'Sehiv secdesi yapıp tamamlar', isCorrect: false },
      { text: 'Namazı akşam vaktine erteler', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindi namazının farzında rükûdan doğrulmadan secdeye gidilirse ne olur?',
    explanation:
      'Rükûdan sonra kâmet (doğrulma) Hanefîlerde vaciptir. Yanılarak terkedilirse namazın sonunda sehiv secdesi yapılır.',
    difficulty: 3,
    options: [
      { text: 'Sehiv secdesi yapılarak namaz tamamlanır', isCorrect: true },
      { text: 'Namaz hemen geçersiz olur', isCorrect: false },
      { text: 'O rekat yeniden kılınır', isCorrect: false },
      { text: 'Hiçbir işlem gerekmez', isCorrect: false },
    ],
  },
  {
    prompt: 'İkindi vaktinde kılınabilecek nafile namaz var mıdır?',
    explanation:
      'İkindinin farzından önce dört rekat gayr-i müekked sünnet kılınabilir. Farzdan sonra ise nafile kılınması hoş görülmemiştir.',
    difficulty: 2,
    options: [
      { text: 'İkindi vaktinde hiç nafile kılınmaz', isCorrect: false },
      { text: 'Yalnızca vitir namazı kılınabilir', isCorrect: false },
      { text: 'Farzdan sonra dört rekat sünnet kılınır', isCorrect: false },
      { text: 'Farzdan önce dört rekat sünnet kılınabilir', isCorrect: true },
    ],
  },
  {
    prompt: 'İkindi namazını vaktinde kılmanın önemi neden vurgulanır?',
    explanation:
      'İkindi namazı, gün içindeki meşguliyetin en yoğun olduğu vakte denk geldiği için özellikle korunması tavsiye edilmiş; hadislerde bu namazı kaçırmanın ağır bir kayıp olduğu bildirilmiştir.',
    difficulty: 1,
    options: [
      { text: 'Kaçırılması ağır bir kayıp olarak bildirilmiştir', isCorrect: true },
      { text: 'Kazası mümkün olmadığı için', isCorrect: false },
      { text: 'Yalnızca Cuma günleri farz olduğu için', isCorrect: false },
      { text: 'Diğer namazların yerine geçtiği için', isCorrect: false },
    ],
  },
];
