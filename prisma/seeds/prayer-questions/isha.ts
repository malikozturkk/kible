import { SeedPrayerQuestion } from '../seed-types';

export const ISHA_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Yatsı namazının farzı kaç rekattır?',
    explanation:
      'Yatsı farzı 4 rekattır. İlk iki rekat cehrî, son iki rekat ise sirrî okunur (öğle ve ikindiden farkı buradadır).',
    difficulty: 1,
    options: [
      { text: '6 rekat', isCorrect: false },
      { text: '2 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: true },
    ],
  },
  {
    prompt: 'Yatsı farzının kıraati nasıl yapılır?',
    explanation:
      'Yatsı farzının ilk iki rekatı cehrî (sesli), son iki rekatı ise sirrî (sessiz) okunur. Sabah ve akşam ile birlikte cehrî namazlardandır.',
    difficulty: 2,
    options: [
      { text: 'Tamamı sessiz', isCorrect: false },
      { text: 'İlk 2 rekat sesli, son 2 rekat sessiz', isCorrect: true },
      { text: 'Tamamı sesli', isCorrect: false },
      { text: 'Sadece son rekat sesli', isCorrect: false },
    ],
  },
  {
    prompt: 'Hanefî mezhebinde vitir namazının hükmü nedir?',
    explanation:
      'Hanefîlere göre vitir vaciptir. Yatsı vakti içinde, yatsının farzından sonra kılınır. 3 rekat olup son rekatta zammı sureden sonra tekbir alınıp Kunut duası okunur.',
    difficulty: 2,
    options: [
      { text: 'Farzdır', isCorrect: false },
      { text: 'Sünnettir', isCorrect: false },
      { text: 'Müstehaptır', isCorrect: false },
      { text: 'Vaciptir', isCorrect: true },
    ],
  },
  {
    prompt: 'Vitir namazı kaç rekattır (Hanefî)?',
    explanation:
      'Hanefîde vitir 3 rekat tek selâmla kılınır; 2. rekat sonunda oturulup yalnız Tahiyyât okunur, 3. rekatta Fatiha + zammı sure ardından kunut yapılır.',
    difficulty: 2,
    options: [
      { text: '2 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: true },
      { text: '5 rekat', isCorrect: false },
      { text: '1 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Yatsı vakti ne zaman başlar?',
    explanation:
      'Yatsı vakti, batı ufkunda akşamın şafağının (kızıllık/beyazlık) kaybolmasıyla başlar ve ikinci fecre (imsak) kadar sürer.',
    difficulty: 2,
    options: [
      { text: 'Güneş batar batmaz', isCorrect: false },
      { text: 'Şafak kaybolunca', isCorrect: true },
      { text: 'Gece yarısı', isCorrect: false },
      { text: 'İmsakla birlikte', isCorrect: false },
    ],
  },
  {
    prompt: 'Vitir namazını yatsıdan önce kılmak câiz midir?',
    explanation:
      'Vitir, yatsı farzı kılındıktan sonra kılınır. Yatsının farzı kılınmadan önce vitir kılınmaz; aksi halde yatsı kılındıktan sonra vitri iade etmek gerekir.',
    difficulty: 3,
    options: [
      { text: 'Sadece seferî için câizdir', isCorrect: false },
      { text: 'Evet, her zaman câizdir', isCorrect: false },
      { text: "Sadece Ramazan'da câizdir", isCorrect: false },
      { text: 'Hayır; yatsı farzından sonra kılınır', isCorrect: true },
    ],
  },
  {
    prompt: 'Vitir namazının kazası gerekir mi?',
    explanation:
      'Vitir vacip olduğu için kazaya kalırsa kaza edilmesi gerekir. Sabah uyanan kişi, kerâhet vakti dışında vitri kaza eder.',
    difficulty: 3,
    options: [
      { text: 'Yalnız Cuma günü kaza edilir', isCorrect: false },
      { text: 'Evet; vacip olduğu için kazası lazımdır', isCorrect: true },
      { text: 'Hayır; sünnet olduğu için kazası yoktur', isCorrect: false },
      { text: 'Sadece üç gün içinde kaza edilir', isCorrect: false },
    ],
  },
  {
    prompt: 'Yatsı namazının ilk sünneti (4 rekat) hangi sünnet türündendir?',
    explanation:
      'Yatsının ilk 4 rekat sünneti gayri müekkeddir; son sünneti olan 2 rekat ise müekkeddir.',
    difficulty: 3,
    options: [
      { text: 'Farz-ı kifâye', isCorrect: false },
      { text: 'Vacip', isCorrect: false },
      { text: 'Gayri müekked sünnet', isCorrect: true },
      { text: 'Müekked sünnet', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazı hangi vakitte kılınır?',
    explanation:
      'Teravih yalnız Ramazan ayında, yatsı namazından sonra ve vitir namazından önce (veya sonrasında) kılınır. Yatsının farzı kılınmadan teravih kılınmaz.',
    difficulty: 3,
    options: [
      { text: 'Vitirden sonra fecre kadar her vakit', isCorrect: false },
      { text: 'Akşamla yatsı arası, yatsıdan önce', isCorrect: false },
      { text: 'Yatsı farzından sonra', isCorrect: true },
      { text: 'Yatsı farzından önce', isCorrect: false },
    ],
  },
  {
    prompt: 'Hanefîye göre yatsı vaktinin en faziletli kılınma vakti hangisidir?',
    explanation:
      'Hanefîlere göre yatsı namazını gecenin üçte birine kadar geciktirmek müstehaptır. Gece yarısından sonraya bırakmak ise mekruhtur.',
    difficulty: 3,
    options: [
      { text: 'Vakit girer girmez kılmak müekkeddir', isCorrect: false },
      { text: 'Gece yarısından sonraya bırakmak', isCorrect: false },
      { text: 'Sabaha yakın kılmak', isCorrect: false },
      { text: 'Gecenin ilk üçte birine kadar geciktirmek', isCorrect: true },
    ],
  },
  {
    prompt: 'Vitir namazının 3. rekatında okunan dua hangisidir?',
    explanation:
      '3. rekatta zammı sureden sonra eller kulak hizasına kaldırılıp tekbir alınır, ardından bağlanır ve "Allâhümme innâ neste\'înüke..." ile başlayan kunut duası okunur.',
    difficulty: 2,
    options: [
      { text: 'Kunut duası', isCorrect: true },
      { text: 'Rabbenâ âtinâ', isCorrect: false },
      { text: 'Tahiyyât', isCorrect: false },
      { text: 'Salli-Bârik', isCorrect: false },
    ],
  },
  {
    prompt: 'Yatsı vakti içinde uyuyakalıp namazı kaçıran kişi sabah uyandığında ne yapar?',
    explanation:
      'Vakit çıktığı için yatsı farzını ve vitri kerâhet vakti dışında ilk fırsatta kaza eder. Tertip sahibi ise kazaya bıraktığı namazları sıraya göre kılar.',
    difficulty: 2,
    options: [
      { text: 'Hem yatsıyı hem vitri kaza eder', isCorrect: true },
      { text: 'Sadece yatsıyı kaza eder; vitir düşer', isCorrect: false },
      { text: 'Vitri sabaha katar, yatsı düşer', isCorrect: false },
      { text: 'Hiçbir şey yapmaz; sevabı umulur', isCorrect: false },
    ],
  },
  {
    prompt: 'Yatsı vakti ne zaman sona erer?',
    explanation:
      'Yatsı vakti, batı ufkundaki şafağın kaybolmasıyla başlar ve fecr-i sâdıkın doğuşuna, yani sabah vaktinin girmesine kadar devam eder.',
    difficulty: 1,
    options: [
      { text: 'Gece yarısı olduğunda', isCorrect: false },
      { text: 'Sabah vakti (imsak) girdiğinde', isCorrect: true },
      { text: 'Güneş doğduğunda', isCorrect: false },
      { text: 'Teravih bittiğinde', isCorrect: false },
    ],
  },
  {
    prompt: 'Yatsı namazının son sünneti kaç rekattır?',
    explanation:
      'Yatsının farzından sonra iki rekat müekked sünnet kılınır. Bunun ardından vitir namazı kılınarak gecenin farz ve vacip namazları tamamlanır.',
    difficulty: 1,
    options: [
      { text: '2 rekat', isCorrect: true },
      { text: '3 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
      { text: '6 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Vitir namazında kunut duası hangi rekatta okunur (Hanefî)?',
    explanation:
      'Hanefîlerde vitrin üçüncü rekatında Fatiha ve zammı sureden sonra tekbir alınıp eller kaldırılır ve kunut duaları okunur, ardından rükûa gidilir.',
    difficulty: 2,
    options: [
      { text: 'Birinci rekatta, rükûdan sonra', isCorrect: false },
      { text: 'İkinci rekatta, secdeden önce', isCorrect: false },
      { text: 'Üçüncü rekatta, rükûdan önce', isCorrect: true },
      { text: 'Her rekatta ayrı ayrı okunur', isCorrect: false },
    ],
  },
  {
    prompt: 'Vitir namazını gecenin sonunda kılmak isteyen kişi ne yapmalıdır?',
    explanation:
      'Gecenin sonunda kalkacağına güvenen kişinin vitri o vakte bırakması daha faziletlidir. Kalkamayacağından endişe eden ise yatsıdan hemen sonra kılar.',
    difficulty: 2,
    options: [
      { text: 'Vitri sabah namazıyla birlikte kılmalıdır', isCorrect: false },
      { text: 'Her hâlükârda yatsıdan hemen sonra kılmalıdır', isCorrect: false },
      { text: 'Kalkacağına güveniyorsa gecenin sonuna bırakabilir', isCorrect: true },
      { text: 'Her hâlükârda gecenin sonuna bırakmalıdır', isCorrect: false },
    ],
  },
  {
    prompt: 'Seferî olan kişi yatsı namazının farzını kaç rekat kılar?',
    explanation:
      'Yolculukta dört rekatlı farzlar iki rekata indirilir. Yatsının farzı seferî için iki rekattır; vitir ise kısaltılmaz, üç rekat kılınır.',
    difficulty: 2,
    options: [
      { text: '2 rekat', isCorrect: true },
      { text: '1 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Yatsı namazını cemaatle kılmanın önemi hakkında ne bildirilmiştir?',
    explanation:
      'Hz. Peygamber yatsı ve sabah namazlarını cemaatle kılmanın ağırlığına dikkat çekmiş, bu iki namazı cemaatle kılanın büyük bir sevap kazandığını bildirmiştir.',
    difficulty: 2,
    options: [
      { text: "Yalnızca Ramazan'da cemaatle kılınır", isCorrect: false },
      { text: 'Cemaat için en az kırk kişi gerekir', isCorrect: false },
      { text: 'Cemaatle kılınması hoş görülmemiştir', isCorrect: false },
      { text: 'Sabahla birlikte cemaati en çok vurgulanan namazdır', isCorrect: true },
    ],
  },
  {
    prompt: 'Yatsı namazının farzında ilk oturuş nerede yapılır?',
    explanation:
      "Dört rekatlı farzlarda ikinci rekattan sonra ka'de-i ûlâ için oturulur, yalnızca Tahiyyât okunur ve üçüncü rekat için ayağa kalkılır.",
    difficulty: 2,
    options: [
      { text: 'İkinci rekattan sonra', isCorrect: true },
      { text: 'Birinci rekattan sonra', isCorrect: false },
      { text: 'Üçüncü rekattan sonra', isCorrect: false },
      { text: 'Farzda ilk oturuş yoktur', isCorrect: false },
    ],
  },
  {
    prompt: 'Yatsıyı kılmadan uyuyup gece yarısı uyanan kişi ne yapar?',
    explanation:
      'Yatsı vakti sabah vaktine kadar devam ettiği için, gece uyanan kişi yatsıyı hâlâ vakti içinde kılabilir; vitri de ardından kılar.',
    difficulty: 2,
    options: [
      { text: 'Vakit çıktığı için sadece kaza eder', isCorrect: false },
      { text: 'Sabah namazıyla birlikte kılar', isCorrect: false },
      { text: 'Vakit devam ettiği için yatsıyı kılar', isCorrect: true },
      { text: 'Yalnızca vitri kılar, yatsı düşer', isCorrect: false },
    ],
  },
];
