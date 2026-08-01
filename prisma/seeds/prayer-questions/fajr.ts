import { SeedPrayerQuestion } from '../seed-types';

export const FAJR_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Sabah (fecir) namazının farzı kaç rekattır?',
    explanation:
      'Sabah namazının farzı 2 rekattır. Öncesinde 2 rekat müekked sünnet kılınır; toplamda 4 rekat olur.',
    difficulty: 1,
    options: [
      { text: '3 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
      { text: '2 rekat', isCorrect: true },
      { text: '1 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının farzından önce kaç rekat sünnet kılınır?',
    explanation:
      'Fecir namazının öncesindeki 2 rekat sünnet, sünnetlerin en kuvvetlisi olarak değerlendirilir. Hz. Peygamberin seferde dahi bırakmadığı bilinen sünnetlerdendir.',
    difficulty: 1,
    options: [
      { text: '4 rekat', isCorrect: false },
      { text: 'Sünnet yoktur', isCorrect: false },
      { text: '2 rekat', isCorrect: true },
      { text: '1 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının farzında kıraat (Fatiha ve zammı sure) nasıl yapılır?',
    explanation:
      'Sabah namazı cehrî (sesli) namazlardandır. İmam veya yalnız kılan kişi, ilk iki rekatın Fatiha ve zammı suresini cemaatin duyabileceği şekilde sesli okur.',
    difficulty: 1,
    options: [
      { text: 'Sesli (cehrî) olarak', isCorrect: true },
      { text: 'Sessiz (sirrî) olarak', isCorrect: false },
      { text: 'Sadece Fatiha sesli, zammı sure sessiz', isCorrect: false },
      { text: 'İmam sessiz, cemaat sesli okur', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının vakti ne zaman sona erer?',
    explanation:
      'Sabah namazının vakti, fecr-i sâdıktan (imsak) güneşin doğmaya başladığı ana (şuruk) kadardır. Güneş ufukta görünmeye başladıktan sonra kılınması doğru değildir.',
    difficulty: 1,
    options: [
      { text: 'Güneş tepe noktasına geldiğinde', isCorrect: false },
      { text: 'İkindi vakti girdiğinde', isCorrect: false },
      { text: 'Güneş doğmaya başladığında', isCorrect: true },
      { text: 'Kuşluk vakti çıktığında', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah ezanında diğer ezanlardan farklı olarak okunan ek cümle nedir?',
    explanation:
      '"es-Salâtu hayrun mine\'n-nevm" — "Namaz uykudan hayırlıdır" cümlesi yalnızca sabah ezanında, "hayye ale\'l-felâh"tan sonra iki defa okunur.',
    difficulty: 2,
    options: [
      { text: "Hayye alâ hayri'l-amel", isCorrect: false },
      { text: 'Lâ ilâhe illallâh (üç kez)', isCorrect: false },
      { text: 'Allâhümme bârik (ek olarak)', isCorrect: false },
      { text: "es-Salâtu hayrun mine'n-nevm", isCorrect: true },
    ],
  },
  {
    prompt: 'Hanefî mezhebine göre sabah namazının farzında kunut duası okunur mu?',
    explanation:
      'Hanefî mezhebinde kunut yalnızca vitir namazında okunur. Şâfiî mezhebinde ise sabah namazının ikinci rekatının rükûsundan sonra kunut okunması sünnettir.',
    difficulty: 3,
    options: [
      { text: 'Her iki rekatta da okunur', isCorrect: false },
      { text: 'Okunmaz; kunut yalnız vitirdedir', isCorrect: true },
      { text: 'Sadece 1. rekatta okunur', isCorrect: false },
      { text: 'Sadece cemaatle kılınırken okunur', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının farzı kaçırılırsa (kazaya kalırsa) ne yapılır?',
    explanation:
      'Hanefîlere göre o gün güneş tepe noktasına (zevâl) ulaşmadan önce sabah namazının farzı ile sünneti birlikte kaza edilir. Zevâlden sonra ise yalnız farzı kaza edilir, sünneti kaza edilmez.',
    difficulty: 3,
    options: [
      { text: 'Zevâle kadar farz ve sünnet birlikte kaza edilir', isCorrect: true },
      { text: 'Sadece sünneti kaza edilir', isCorrect: false },
      { text: 'Hiçbir şekilde kaza edilmez', isCorrect: false },
      { text: 'Ertesi gün sabah birlikte kılınır', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının vakti hangi olayla başlar?',
    explanation:
      'Vakit, fecr-i sâdık dediğimiz, ufukta enine yayılan ikinci beyazlığın belirmesiyle başlar. Bu, imsak vaktidir; oruçlular için yeme-içmenin kesildiği andır.',
    difficulty: 2,
    options: [
      { text: 'Fecr-i sâdık (imsak)', isCorrect: true },
      { text: 'Güneşin doğması', isCorrect: false },
      { text: 'Şafakın kaybolması', isCorrect: false },
      { text: 'Güneşin bir mızrak boyu yükselmesi', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının sünneti için tavsiye edilen kıraat hangisidir?',
    explanation:
      'Hz. Peygamberin sabah sünnetinin birinci rekatında Kâfirûn, ikinci rekatında İhlâs sûresini okuduğu rivayet edilmiştir.',
    difficulty: 2,
    options: [
      { text: 'Sadece Fatiha okunur', isCorrect: false },
      { text: 'İki rekat Ayetel Kürsi', isCorrect: false },
      { text: '1. rekatta Kâfirûn, 2. rekatta İhlâs', isCorrect: true },
      { text: '1. rekatta Felak, 2. rekatta Nâs', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazından sonra güneş doğuncaya kadar nafile namaz kılmak nasıldır?',
    explanation:
      'Sabah farzından sonra güneşin doğmasına ve bir mızrak boyu yükselmesine kadar olan süre kerâhet vaktidir; bu vakit içinde nafile namaz kılmak mekruhtur.',
    difficulty: 3,
    options: [
      { text: 'Müstehaptır', isCorrect: false },
      { text: 'Vaciptir', isCorrect: false },
      { text: 'Mekruhtur (kerâhet vakti)', isCorrect: true },
      { text: 'Sadece tesbih namazı kılınabilir', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının farzı kaç oturuş içerir?',
    explanation:
      '2 rekatlı olduğu için yalnız son oturuş vardır. Burada Tahiyyât, Salli-Bârik ve dua okunur, ardından selam verilir.',
    difficulty: 2,
    options: [
      { text: '2 (ara ve son oturuş)', isCorrect: false },
      { text: 'Oturuş yoktur', isCorrect: false },
      { text: '3 oturuş', isCorrect: false },
      { text: '1 (son oturuş)', isCorrect: true },
    ],
  },
  {
    prompt: "Cemaatle sabah namazı kılınırken cemaat Fatiha'yı nasıl okur (Hanefî)?",
    explanation:
      'Hanefîlere göre cehrî namazlarda cemaat hiçbir şey okumaz; imamın kıraati cemaat için de yeterlidir. Cemaat yalnız susarak dinler.',
    difficulty: 3,
    options: [
      { text: 'İmamla birlikte sesli okur', isCorrect: false },
      { text: 'Okumaz; susarak imamı dinler', isCorrect: true },
      { text: 'Sadece içinden Fatiha okur', isCorrect: false },
      { text: 'Sadece zammı sureyi okur', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının sünneti ile farzı arasında konuşmak namazı bozar mı?',
    explanation:
      'Sünnet ile farz ayrı namazlardır; aralarında konuşmak farzı bozmaz. Ancak vakti daraltacak veya cemaati kaçıracak uzun sohbet hoş görülmemiştir.',
    difficulty: 2,
    options: [
      { text: 'Hayır, ikisi ayrı namaz olduğu için bozmaz', isCorrect: true },
      { text: 'Evet, ikisi tek namaz sayıldığı için bozar', isCorrect: false },
      { text: 'Sadece cemaatle kılınıyorsa bozar', isCorrect: false },
      { text: 'Sadece imam konuşursa bozar', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazını cemaatle kılmanın fazileti hakkında ne söylenir?',
    explanation:
      'Hz. Peygamber cemaatle kılınan namazın tek başına kılınandan yirmi yedi derece üstün olduğunu bildirmiştir. Bu ölçü sabah namazı için de geçerlidir.',
    difficulty: 1,
    options: [
      { text: 'Tek başına kılmakla tamamen eşittir', isCorrect: false },
      { text: 'Sadece Ramazan ayında faziletlidir', isCorrect: false },
      { text: 'Tek başına kılmaktan çok daha faziletlidir', isCorrect: true },
      { text: 'Sadece mescide yakın oturana faziletlidir', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının farzına niyet ederken kalpten geçirilmesi gereken nedir?',
    explanation:
      'Niyetin aslı kalbin kararıdır: hangi namazın kılındığını bilmek yeterlidir. Dil ile söylemek şart değil, sünnet olarak görülmüştür.',
    difficulty: 1,
    options: [
      { text: 'Niyeti mutlaka yüksek sesle söylemek', isCorrect: false },
      { text: 'Rekat sayısını parmakla saymak', isCorrect: false },
      { text: 'Hangi namazı kıldığını kalben bilmek', isCorrect: true },
      { text: 'Kıbleyi pusula ile doğrulamak', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının sünnetini kılarken farza cemaatle başlanırsa ne yapılır?',
    explanation:
      'Hanefîlere göre sünneti mescidin dışında veya bir kenarda tamamlayıp farza yetişmeye çalışılır; farzın ilk rekatına yetişme imkânı yoksa sünnet bırakılıp imama uyulur.',
    difficulty: 3,
    options: [
      { text: 'Cemaate yetişme durumuna göre karar verilir', isCorrect: true },
      { text: 'Her hâlükârda sünnet bırakılır', isCorrect: false },
      { text: 'Her hâlükârda sünnet tamamlanır', isCorrect: false },
      { text: 'Namaz baştan yeniden başlatılır', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazı için abdesti olmayan kişi su bulamazsa ne yapar?',
    explanation:
      'Su bulunmadığında veya kullanmaya engel bir durum varsa temiz toprak cinsinden bir şeyle teyemmüm edilir ve namaz vaktinde kılınır.',
    difficulty: 2,
    options: [
      { text: 'Su bulana kadar namazı erteler', isCorrect: false },
      { text: 'Teyemmüm eder ve namazını vaktinde kılar', isCorrect: true },
      { text: 'Abdestsiz olarak namazını kılar', isCorrect: false },
      { text: 'O günün namazını hiç kılmaz', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının farzında yanlışlıkla bir vacip terkedilirse ne gerekir?',
    explanation:
      'Namazın vaciplerinden biri yanılarak terkedilirse namazın sonunda sehiv secdesi yapılır. Kasten terkedilmişse namazın iadesi gerekir.',
    difficulty: 3,
    options: [
      { text: 'Namaz kendiliğinden geçersiz olur', isCorrect: false },
      { text: 'Yalnızca istiğfar edilir', isCorrect: false },
      { text: 'Bir sonraki namaza eklenir', isCorrect: false },
      { text: 'Sehiv secdesi yapılır', isCorrect: true },
    ],
  },
  {
    prompt: 'Sabah namazı vaktinde uyanamayan kişi ne zaman kaza eder?',
    explanation:
      'Uyku ile namazı kaçıran kişi günahkâr olmaz; uyandığı anda kerâhet vakti değilse hemen kaza eder. Sabah namazının sünneti de güneş doğduktan sonra farzla birlikte kaza edilir.',
    difficulty: 2,
    options: [
      { text: 'Uyandığında kerâhet vakti dışında hemen kaza eder', isCorrect: true },
      { text: 'Ertesi günün sabah vaktini bekler', isCorrect: false },
      { text: 'Namazı kaza etmesi gerekmez', isCorrect: false },
      { text: 'Yalnızca ertesi Cuma günü kaza eder', isCorrect: false },
    ],
  },
  {
    prompt: 'Sabah namazının farzının ikinci rekatında ne yapılır?',
    explanation:
      'İkinci rekatta Fatiha ve zammı sure okunur, rükû ve secdelerden sonra oturularak Tahiyyât, salavat ve dua okunup selâm verilir.',
    difficulty: 1,
    options: [
      { text: 'Kıraat okunmadan doğrudan secdeye gidilir', isCorrect: false },
      { text: 'Ayakta Tahiyyât okunup selâm verilir', isCorrect: false },
      { text: 'Üçüncü rekat için tekrar ayağa kalkılır', isCorrect: false },
      { text: 'Kıraatten sonra oturulup Tahiyyât okunur', isCorrect: true },
    ],
  },
];
