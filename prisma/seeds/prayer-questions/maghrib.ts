import { SeedPrayerQuestion } from '../seed-types';

export const MAGHRIB_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Akşam namazının farzı kaç rekattır?',
    explanation:
      'Akşam farzı 3 rekattır ve gündüzün vitri olarak nitelenir. Tek rekatlı olması bakımından beş vakit içinde tektir.',
    difficulty: 1,
    options: [
      { text: '2 rekat', isCorrect: false },
      { text: '5 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: true },
    ],
  },
  {
    prompt: 'Akşam namazı sünnet dahil toplam kaç rekattır?',
    explanation:
      'Akşam: 3 farz + 2 son sünnet (müekked) = 5 rekat. Öncesinde farz olarak nitelenmiş bir sünnet yoktur.',
    difficulty: 1,
    options: [
      { text: '3 rekat (yalnız farz)', isCorrect: false },
      { text: '5 rekat (3+2)', isCorrect: true },
      { text: '9 rekat', isCorrect: false },
      { text: '7 rekat (3+4)', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam farzının kıraati nasıl yapılır?',
    explanation:
      'Akşam farzının ilk iki rekatı cehrî (sesli), üçüncü rekatı ise sirrî (sessiz) okunur. 3. rekatta yalnız Fatiha okunur, zammı sure eklenmez.',
    difficulty: 2,
    options: [
      { text: 'Tamamı sesli', isCorrect: false },
      { text: 'Tamamı sessiz', isCorrect: false },
      { text: 'Sadece son rekat sesli', isCorrect: false },
      { text: 'İlk 2 rekat sesli, 3. rekat sessiz', isCorrect: true },
    ],
  },
  {
    prompt: 'Akşam vakti ne zaman başlar?',
    explanation: 'Akşam vakti, güneşin batmasıyla başlar. İftar vakti ile aynı andır.',
    difficulty: 1,
    options: [
      { text: 'Yıldızların görünmesiyle', isCorrect: false },
      { text: 'Güneşin batmasıyla', isCorrect: true },
      { text: 'Şafakın kaybolmasıyla', isCorrect: false },
      { text: 'Güneşin sararmasıyla', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam vakti ne zaman çıkar?',
    explanation:
      "Akşam vakti, batı ufkundaki şafağın (kırmızılığın, Ebû Hanîfe'ye göre beyazlığın) kaybolmasıyla biter ve yatsı vakti başlar.",
    difficulty: 2,
    options: [
      { text: 'Bir saat sonra', isCorrect: false },
      { text: 'Şafak (kızıllık/beyazlık) kayboluncaya kadar', isCorrect: true },
      { text: 'Yatsı ezanına 30 dk kala', isCorrect: false },
      { text: 'Güneşin doğmasıyla', isCorrect: false },
    ],
  },
  {
    prompt: "Akşam namazının farzında 3. rekatta Fatiha'dan sonra zammı sure okunur mu?",
    explanation:
      'Akşamın 3. rekatında yalnız Fatiha okunur. Öğle/ikindi/yatsının 3-4. rekatlarındaki uygulama gibi, zammı sure eklenmez.',
    difficulty: 2,
    options: [
      { text: 'Okunmaz; yalnız Fatiha okunur', isCorrect: true },
      { text: 'Kısa bir sure okunur', isCorrect: false },
      { text: 'Ayetel Kürsi okunur', isCorrect: false },
      { text: 'İhlâs okunması vaciptir', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam namazını sebepsiz geciktirmek nasıldır?',
    explanation:
      'Akşam namazını yıldızlar görünene veya gecenin ileri saatlerine bırakmak mekruhtur. Vakit girer girmez kısa sürede kılınması müstehaptır.',
    difficulty: 2,
    options: [
      { text: 'Mekruhtur', isCorrect: true },
      { text: 'Müstehaptır', isCorrect: false },
      { text: 'Vaciptir', isCorrect: false },
      { text: 'Fazileti artırır', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşamın son sünneti 2 rekat olarak nasıl kılınır?',
    explanation:
      'Tek selamla iki rekat halinde kılınır; ilk rekatta Fatiha + zammı sure, son oturuşta Tahiyyât + Salli-Bârik + dua okunarak selâm verilir.',
    difficulty: 2,
    options: [
      { text: 'Dört rekat tek selâmla', isCorrect: false },
      { text: 'Tek selamla, iki rekat olarak', isCorrect: true },
      { text: 'Üç rekat tek selâm ile', isCorrect: false },
      { text: 'Her rekatta selâm verilerek', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam namazında kaç oturuş bulunur?',
    explanation:
      '3 rekatlı olduğu için 2 oturuş vardır: 2. rekatın sonundaki kâde-i ûlâ (vacip) ile 3. rekatın sonundaki kâde-i ahîre (farz).',
    difficulty: 2,
    options: [
      { text: 'Oturuş yoktur', isCorrect: false },
      { text: '2 oturuş', isCorrect: true },
      { text: '1 oturuş', isCorrect: false },
      { text: '3 oturuş', isCorrect: false },
    ],
  },
  {
    prompt:
      'Akşam namazına imama 3. rekatta yetişen kişi, imam selâm verdikten sonra kaçar rekat tek başına tamamlar?',
    explanation:
      'İmama 3. rekatta yetişen kişi imamla birlikte selâm vermez; kalkıp eksik 2 rekatı, Fatiha + zammı sure okuyarak iki rekat olarak tamamlar.',
    difficulty: 3,
    options: [
      { text: '2 rekat (her ikisinde Fatiha + zammı sure)', isCorrect: true },
      { text: '3 rekat (her birinde Fatiha)', isCorrect: false },
      { text: 'Hiç; imamla selâm verir', isCorrect: false },
      { text: '1 rekat (yalnız Fatiha)', isCorrect: false },
    ],
  },
  {
    prompt: 'Seferî olan kişi akşam namazının farzını kaç rekat kılar?',
    explanation:
      'Akşam, sabah ve vitir namazları seferî olsa dahi kasr edilmez; akşam yine 3 rekat olarak kılınır.',
    difficulty: 3,
    options: [
      { text: '1 rekat', isCorrect: false },
      { text: '2 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
      { text: '3 rekat (kasr edilmez)', isCorrect: true },
    ],
  },
  {
    prompt: 'Akşam namazından sonra "evvâbîn namazı" olarak kılınabilecek nafile kaç rekattır?',
    explanation:
      'Akşam farz ve müekked sünnetinden sonra kılınan, hadislerde teşvik edilen 6 rekatlık nafile namaz "evvâbîn" olarak isimlendirilir.',
    difficulty: 3,
    options: [
      { text: '2 rekat', isCorrect: false },
      { text: '8 rekat', isCorrect: false },
      { text: '6 rekat', isCorrect: true },
      { text: '4 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam namazının farzının hangi rekatlarında kıraat sesli yapılır?',
    explanation:
      'Akşam namazı cehrî namazlardandır. Farzın ilk iki rekatında Fatiha ve zammı sure sesli, üçüncü rekatta ise yalnızca Fatiha sessiz okunur.',
    difficulty: 2,
    options: [
      { text: 'Üç rekatın tamamında sessiz', isCorrect: false },
      { text: 'Üç rekatın tamamında sesli', isCorrect: false },
      { text: 'Yalnızca üçüncü rekatta sesli', isCorrect: false },
      { text: 'İlk iki rekatta sesli, üçüncüde sessiz', isCorrect: true },
    ],
  },
  {
    prompt: 'Oruçlu bir kişi akşam namazından önce mi sonra mı iftar eder?',
    explanation:
      'Güneş battığı anda oruç açılır; sünnet olan hafif bir şeyle iftar edip akşam namazını kılmak, ardından yemeğe devam etmektir.',
    difficulty: 1,
    options: [
      { text: 'İftar etmeden namazı kılması zorunludur', isCorrect: false },
      { text: 'Akşam namazını iftardan bir saat sonra kılar', isCorrect: false },
      { text: 'Hafifçe iftar eder, sonra namazı kılar', isCorrect: true },
      { text: 'Yatsı namazına kadar iftarı bekletir', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam namazının vakti diğer vakitlere göre neden daha kısadır?',
    explanation:
      'Akşam vakti güneşin batışıyla başlar ve batı ufkundaki kızıllığın (şafak) kaybolmasıyla, yani yatsı vaktinin girmesiyle sona erer. Bu aralık diğer vakitlere göre kısadır.',
    difficulty: 2,
    options: [
      { text: 'Sadece üç rekat olduğu için', isCorrect: false },
      { text: 'Kerâhet vaktine denk geldiği için', isCorrect: false },
      { text: 'Şafak kaybolunca yatsı vakti girdiği için', isCorrect: true },
      { text: 'Güneş tam tepede olduğu için', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam namazının farzını üç rekat yerine dört rekat kılan kişi ne yapar?',
    explanation:
      'Üçüncü rekattan sonra oturulmuşsa fazladan kılınan rekat nafileye dönüşür ve sehiv secdesi yapılır. Hiç oturulmamışsa farz geçersiz olur ve yeniden kılınır.',
    difficulty: 3,
    options: [
      { text: 'Her durumda namazı geçersizdir', isCorrect: false },
      { text: 'Fazla rekatı yatsıya sayar', isCorrect: false },
      { text: 'Üçüncüde oturmuşsa sehiv secdesiyle tamamlar', isCorrect: true },
      { text: 'Her durumda namazı geçerli sayılır', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam namazının farzına imama ikinci rekatta yetişen kişi kaç rekat tamamlar?',
    explanation:
      'İmamla iki rekat kılmış olur; imam selâm verdikten sonra kalkıp yetişemediği bir rekatı Fatiha ve zammı sure ile tek başına tamamlar.',
    difficulty: 2,
    options: [
      { text: '1 rekat', isCorrect: true },
      { text: 'Tamamlaması gerekmez', isCorrect: false },
      { text: '3 rekat', isCorrect: false },
      { text: '2 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam namazının farzında ikinci rekattan sonra oturmak nedir?',
    explanation:
      "Üç ve dört rekatlı namazlarda ikinci rekattan sonraki oturuş ka'de-i ûlâdır ve Hanefîlerde vaciptir. Terkedilirse sehiv secdesi gerekir.",
    difficulty: 3,
    options: [
      { text: 'Müstehaptır, isteğe bağlıdır', isCorrect: false },
      { text: 'Sünnettir, terkinde bir şey gerekmez', isCorrect: false },
      { text: "Ka'de-i ahîredir ve farzdır", isCorrect: false },
      { text: "Ka'de-i ûlâdır ve vaciptir", isCorrect: true },
    ],
  },
  {
    prompt: 'Akşam namazının son sünnetinden sonra okunması tavsiye edilen nedir?',
    explanation:
      "Namazlardan sonra tesbihat yapmak, Âyetü'l-Kürsî ve tesbih-tahmid-tekbirleri okumak sünnettir. Akşam namazı için de aynı tesbihat tavsiye edilmiştir.",
    difficulty: 1,
    options: [
      { text: "Âyetü'l-Kürsî ve namaz tesbihatı", isCorrect: true },
      { text: 'Teşehhüd ve selâm', isCorrect: false },
      { text: 'Yalnızca Fatiha suresi', isCorrect: false },
      { text: 'Kunut duaları', isCorrect: false },
    ],
  },
  {
    prompt: 'Akşam vakti girmeden akşam namazını kılan kişinin namazı ne olur?',
    explanation:
      'Vaktin girmesi namazın şartlarındandır. Vakit girmeden kılınan farz geçerli olmaz; vakit girince yeniden kılınması gerekir.',
    difficulty: 2,
    options: [
      { text: 'Geçerlidir, erken kılmak faziletlidir', isCorrect: false },
      { text: 'Nafile olarak geçerli, farz olarak da sayılır', isCorrect: false },
      { text: 'Geçerli olmaz, vakit girince yeniden kılar', isCorrect: true },
      { text: 'Sehiv secdesiyle geçerli hâle gelir', isCorrect: false },
    ],
  },
];
