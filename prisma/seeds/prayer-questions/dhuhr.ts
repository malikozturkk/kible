import { SeedPrayerQuestion } from '../seed-types';

export const DHUHR_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Öğle namazının farzı kaç rekattır?',
    explanation:
      'Öğle namazının farzı 4 rekattır; sirrî (sessiz) okunur. Tüm dört rekatta da Fatiha okunur, ilk iki rekatta ayrıca zammı sure eklenir.',
    difficulty: 1,
    options: [
      { text: '2 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: true },
      { text: '6 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazı sünnetler dahil toplam kaç rekattır?',
    explanation:
      'Öğle: 4 ilk sünnet (müekked) + 4 farz + 2 son sünnet (müekked) = 10 rekat. Cuma günleri farz yerine Cuma namazı kılınır.',
    difficulty: 1,
    options: [
      { text: '8 rekat', isCorrect: false },
      { text: '12 rekat', isCorrect: false },
      { text: '10 rekat (4+4+2)', isCorrect: true },
      { text: '4 rekat (sadece farz)', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazının kıraati nasıl yapılır?',
    explanation:
      'Öğle namazı sirrî (sessiz) namazlardandır. İmam dahi farzda Fatiha ve sureyi içinden okur; ses çıkarmaz.',
    difficulty: 1,
    options: [
      { text: 'İmam sesli, münferid sessiz', isCorrect: false },
      { text: 'İlk iki rekat sesli, son iki rekat sessiz', isCorrect: false },
      { text: 'Sesli (cehrî)', isCorrect: false },
      { text: 'Sessiz (sirrî)', isCorrect: true },
    ],
  },
  {
    prompt: 'Öğle vakti ne zaman başlar?',
    explanation:
      'Öğle vakti, güneşin tam tepe noktasından (istivâ) batıya doğru kaymaya başlamasıyla (zevâl) girer.',
    difficulty: 2,
    options: [
      { text: 'Kuşluk vaktinin sonunda', isCorrect: false },
      { text: 'Güneşin zevâlden batıya kayması ile', isCorrect: true },
      { text: 'Güneşin doğuşu ile', isCorrect: false },
      { text: 'Eşyanın gölgesi kendisinin iki katı olunca', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle vakti ne zaman çıkar?',
    explanation:
      'Hanefîlerde imâmeyn (Ebû Yûsuf ve Muhammed) görüşüne göre öğle vakti, her şeyin gölgesi kendisi kadar oluncaya kadardır; bu görüş fetvada esastır.',
    difficulty: 3,
    options: [
      { text: 'Güneş batınca', isCorrect: false },
      { text: 'Güneş tam tepedeyken', isCorrect: false },
      { text: 'Eşyanın gölgesi kendisi kadar olunca', isCorrect: true },
      { text: 'İmsak vakti ile birlikte', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazının farzından önce kaç rekat sünnet kılınır?',
    explanation:
      'Öğlenin ilk sünneti 4 rekat olup müekked sünnetlerdendir. Tek selamla, iki oturuşla kılınır.',
    difficulty: 1,
    options: [
      { text: '6 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: true },
      { text: 'Sünnet yoktur', isCorrect: false },
      { text: '2 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazının farzından sonra kaç rekat sünnet kılınır?',
    explanation:
      'Farzdan sonra kılınan 2 rekat son sünnet de müekkeddir. Bazıları buna ek 2 rekat daha gayri müekked sünnet kılar.',
    difficulty: 1,
    options: [
      { text: '2 rekat', isCorrect: true },
      { text: '4 rekat', isCorrect: false },
      { text: '1 rekat', isCorrect: false },
      { text: 'Sünnet yoktur', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma günü cemaatle Cuma namazı kılan bir erkek ayrıca öğle namazı kılar mı?',
    explanation:
      'Cuma namazı kendisine farz olan kişiye Cuma kılındığında öğle farzını ayrıca kılmaz; Cuma namazı öğle farzının yerine geçer.',
    difficulty: 2,
    options: [
      { text: 'Sadece 2 rekat kılar', isCorrect: false },
      { text: 'Hayır; Cuma öğlenin yerine geçer', isCorrect: true },
      { text: 'Evet, ayrıca 4 rekat farz kılar', isCorrect: false },
      { text: 'Önce öğle sonra Cuma kılar', isCorrect: false },
    ],
  },
  {
    prompt: "Öğle namazının farzında 3. ve 4. rekatlarda Fatiha'dan sonra zammı sure okunur mu?",
    explanation:
      'Hanefîlerde farzın 3. ve 4. rekatlarında yalnız Fatiha okunur; zammı sure okunmaz. İlk iki rekatta ise Fatiha + zammı sure okunması vaciptir.',
    difficulty: 2,
    options: [
      { text: 'Okunmaz; sadece Fatiha okunur', isCorrect: true },
      { text: 'Sadece 4. rekatta okunur', isCorrect: false },
      { text: 'Sadece Ayetel Kürsi okunur', isCorrect: false },
      { text: 'Okunur; her rekatta Fatiha + sure', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğlenin ilk 4 rekat sünnetinde iki rekatta bir Tahiyyât için oturulur mu?',
    explanation:
      'Öğlenin ilk sünneti dört rekat tek selâmla kılınır. İki rekat sonunda yalnız Tahiyyât okunur; Salli-Bârik okunmaz, ayağa kalkılır ve 3-4. rekatta hem Fatiha hem zammı sure okunur.',
    difficulty: 3,
    options: [
      { text: 'Evet; Tahiyyât + Salli-Bârik okunur', isCorrect: false },
      { text: 'Hayır; oturuş yapılmaz', isCorrect: false },
      { text: 'Evet; Tahiyyât okunur, ardından kalkılır', isCorrect: true },
      { text: 'Hayır; selam verilir, sünnet sonlanır', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazının son sünneti (2 rekat) terkedilirse farz geçerli olur mu?',
    explanation:
      'Sünnetin terki farzı bozmaz; namaz geçerlidir. Ancak müekked sünnet terk edildiğinden sevap eksilir; düzenli terki mekruh olur.',
    difficulty: 2,
    options: [
      { text: 'Evet; farz geçerlidir, sevap eksilir', isCorrect: true },
      { text: 'Hayır; farz da iade edilmelidir', isCorrect: false },
      { text: 'Sadece imam için geçerlidir', isCorrect: false },
      { text: 'Hayır; tek başına farz olmaz', isCorrect: false },
    ],
  },
  {
    prompt: 'Yolcu (seferî) bir kişi öğle namazının farzını kaç rekat kılar?',
    explanation:
      'Seferîlik şartlarını taşıyan kişi öğle, ikindi ve yatsı farzlarını 2 rekat olarak (kasr ederek) kılar. Sünnetler kişinin tercihine bağlıdır, terki günah değildir.',
    difficulty: 3,
    options: [
      { text: '3 rekat', isCorrect: false },
      { text: '4 rekat (tam)', isCorrect: false },
      { text: 'Düşer; kılınmaz', isCorrect: false },
      { text: '2 rekat (kasr)', isCorrect: true },
    ],
  },
  {
    prompt: 'Öğle namazının farzında imama üçüncü rekatta yetişen kişi ne yapar?',
    explanation:
      'İmamla birlikte kalan rekatları kılar, imam selâm verdikten sonra ayağa kalkıp yetişemediği iki rekatı Fatiha ve zammı sure ile tamamlar.',
    difficulty: 2,
    options: [
      { text: 'İmamla birlikte selâm verip namazı bitirir', isCorrect: false },
      { text: 'Namazı baştan yeniden kılar', isCorrect: false },
      { text: 'İmam selâm verince kalan iki rekatı tamamlar', isCorrect: true },
      { text: 'Yalnızca bir rekat daha kılar', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazı için güneşin tam tepede olduğu an (istivâ) ne ifade eder?',
    explanation:
      'Güneşin tam tepe noktasında bulunduğu kısa süre kerâhet vaktidir; öğle vakti güneş bu noktadan batıya doğru kaydıktan (zeval) sonra başlar.',
    difficulty: 2,
    options: [
      { text: 'Öğle namazının en faziletli vaktidir', isCorrect: false },
      { text: 'Öğle vaktinin sona erdiği andır', isCorrect: false },
      { text: 'İkindi vaktinin başladığı andır', isCorrect: false },
      { text: 'Namaz kılınması hoş görülmeyen kerâhet vaktidir', isCorrect: true },
    ],
  },
  {
    prompt: 'Öğle namazının farzını kılarken üçüncü rekatta ayağa kalkmadan oturursa ne olur?',
    explanation:
      'Üçüncü rekat için ayağa kalkmak yerine yanılarak oturan kişi hatırladığında hemen kalkar ve namazın sonunda sehiv secdesi yapar.',
    difficulty: 3,
    options: [
      { text: 'Hemen kalkar ve sonunda sehiv secdesi yapar', isCorrect: true },
      { text: 'Namazı bozup baştan başlar', isCorrect: false },
      { text: 'Oturarak namazı tamamlar', isCorrect: false },
      { text: 'Kalan rekatları kaza olarak kılar', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazının farzında Fatiha okumayı unutan kişi ne yapmalıdır?',
    explanation:
      'Fatiha okumak Hanefîlerde vaciptir; yanılarak terkedildiğinde namazın sonunda sehiv secdesi yapılarak namaz tamamlanır.',
    difficulty: 3,
    options: [
      { text: 'Hiçbir şey yapması gerekmez', isCorrect: false },
      { text: 'O rekatı tekrar kılar', isCorrect: false },
      { text: 'Namazı bozup yeniden kılar', isCorrect: false },
      { text: 'Namazın sonunda sehiv secdesi yapar', isCorrect: true },
    ],
  },
  {
    prompt: 'İşte veya okulda öğle namazını kılacak yer bulamayan kişi ne yapar?',
    explanation:
      'Namaz için özel bir mekân şartı yoktur. Temiz bir yerde kıbleye yönelerek kılınabilir; vakti geçirmemek esastır.',
    difficulty: 1,
    options: [
      { text: 'O günün öğle namazını düşürür', isCorrect: false },
      { text: 'Mescit bulana kadar namazı erteler', isCorrect: false },
      { text: 'Temiz bir yerde kıbleye yönelip vaktinde kılar', isCorrect: true },
      { text: 'Akşam namazıyla birleştirir', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazının farzının son iki rekatında sesli okumak gerekir mi?',
    explanation:
      'Öğle namazı sirrî (sessiz) namazlardandır. Farzın hiçbir rekatında kıraat sesli yapılmaz; son iki rekatta yalnızca Fatiha içten okunur.',
    difficulty: 2,
    options: [
      { text: 'Hayır, tüm kıraat sessiz yapılır', isCorrect: true },
      { text: 'Sadece cemaat sesli okur', isCorrect: false },
      { text: 'Evet, son iki rekat sesli okunur', isCorrect: false },
      { text: 'Sadece imam sesli okur', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazını kılarken vaktin çıktığını fark eden kişi ne yapar?',
    explanation:
      'Vakit içinde başlanan namaz vakit çıksa da tamamlanır. Namaz kesilmez; kalan rekatlar bitirilerek selâm verilir.',
    difficulty: 3,
    options: [
      { text: 'Namazı hemen keser', isCorrect: false },
      { text: 'Namazını keserek değil, tamamlayarak bitirir', isCorrect: true },
      { text: 'Kalan rekatları ikindiye ekler', isCorrect: false },
      { text: 'Namazı ertesi güne kaza bırakır', isCorrect: false },
    ],
  },
  {
    prompt: 'Öğle namazının ilk sünnetini kılamayan kişi bunu farzdan sonra kılabilir mi?',
    explanation:
      'Hanefîlerde öğlenin ilk dört rekat sünneti farzdan sonra da kılınabilir. Tercih edilen, son sünnet kılındıktan sonra kaza edilmesidir.',
    difficulty: 3,
    options: [
      { text: 'Sadece ertesi gün kılabilir', isCorrect: false },
      { text: 'Hayır, tamamen düşer', isCorrect: false },
      { text: 'Sadece cemaatle kılabilir', isCorrect: false },
      { text: 'Evet, vakit içinde farzdan sonra kılabilir', isCorrect: true },
    ],
  },
];
