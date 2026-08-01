import { SeedPrayerQuestion } from '../seed-types';

export const TARAWIH_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Teravih namazı hangi ayda kılınır?',
    explanation:
      'Teravih namazı yalnızca Ramazan ayına mahsus bir nafile namazdır. Ramazan geceleri yatsıdan sonra kılınır.',
    difficulty: 1,
    options: [
      { text: 'Şaban ayında', isCorrect: false },
      { text: 'Zilhicce ayında', isCorrect: false },
      { text: 'Ramazan ayında', isCorrect: true },
      { text: 'Muharrem ayında', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazının hükmü nedir?',
    explanation:
      'Teravih, kadın ve erkek her müslüman için sünnet-i müekkededir. Farz veya vacip değildir; terkedilmesi hâlinde kaza gerekmez.',
    difficulty: 1,
    options: [
      { text: 'Sünnet-i müekkededir', isCorrect: true },
      { text: 'Mekruhtur', isCorrect: false },
      { text: 'Farz-ı ayındır', isCorrect: false },
      { text: 'Vaciptir', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazı hangi vakitte kılınır?',
    explanation:
      'Teravih yatsı namazının farzı kılındıktan sonra başlar ve sabah vakti girene kadar kılınabilir. Yatsıdan önce kılınmaz.',
    difficulty: 1,
    options: [
      { text: 'İftardan hemen önce', isCorrect: false },
      { text: 'Yatsıdan sonra, sabah vaktine kadar', isCorrect: true },
      { text: 'Sahurdan sonra', isCorrect: false },
      { text: 'Akşam ile yatsı arasında', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazı Hanefî uygulamasında kaç rekat kılınır?',
    explanation:
      'Hanefî uygulamasında teravih yirmi rekat olarak kılınır. Genellikle iki rekatta bir selâm verilerek on selâmla tamamlanır.',
    difficulty: 2,
    options: [
      { text: '4 rekat', isCorrect: false },
      { text: '20 rekat', isCorrect: true },
      { text: '12 rekat', isCorrect: false },
      { text: '40 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazı cemaatle kılınabilir mi?',
    explanation:
      'Teravihi cemaatle kılmak sünnet-i kifâyedir; camilerde cemaatle kılınması yaygın uygulamadır. Tek başına kılmak da geçerlidir.',
    difficulty: 1,
    options: [
      { text: 'Hayır, yalnızca tek başına kılınır', isCorrect: false },
      { text: 'Yalnızca Kadir gecesinde cemaatle kılınır', isCorrect: false },
      { text: 'Yalnızca imamın evinde kılınır', isCorrect: false },
      { text: 'Evet, cemaatle kılınması sünnettir', isCorrect: true },
    ],
  },
  {
    prompt: 'Teravih namazı ile vitir namazının sırası nasıldır?',
    explanation:
      "Ramazan'da vitir namazı teravihten sonra kılınır ve cemaatle kılınması câizdir. Teravihe yetişemeyen kişi vitri tek başına da kılabilir.",
    difficulty: 2,
    options: [
      { text: "Ramazan'da vitir kılınmaz", isCorrect: false },
      { text: 'Önce vitir, sonra teravih kılınır', isCorrect: false },
      { text: 'Önce teravih, sonra vitir kılınır', isCorrect: true },
      { text: 'İkisi aynı anda kılınır', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazına yetişemeyen kişi ne yapar?',
    explanation:
      'Teravih nafile bir namazdır; kaçırılması hâlinde kazası gerekmez. Kişi imkân bulursa kalan rekatları tek başına kılabilir.',
    difficulty: 2,
    options: [
      { text: 'Ertesi gün iki kat kılması gerekir', isCorrect: false },
      { text: 'O günün orucu geçersiz olur', isCorrect: false },
      { text: 'Bayram sonrası kaza etmesi gerekir', isCorrect: false },
      { text: 'Kazası gerekmez, dilerse tek başına kılar', isCorrect: true },
    ],
  },
  {
    prompt: 'Teravih namazında her dört rekatın sonunda yapılan kısa aranın adı nedir?',
    explanation:
      'Teravihte dört rekatta bir verilen kısa dinlenme arasına "terviha" denir. Namazın adı da bu kelimeden gelmektedir.',
    difficulty: 3,
    options: [
      { text: 'Teşehhüd', isCorrect: false },
      { text: 'Terviha', isCorrect: true },
      { text: 'Kamet', isCorrect: false },
      { text: 'Kunut', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazında kıraat nasıl yapılır?',
    explanation:
      'Teravih cehrî kılınan bir namazdır; imam Fatiha ve zammı sureyi cemaatin duyacağı şekilde sesli okur.',
    difficulty: 2,
    options: [
      { text: 'Yalnızca son iki rekat sesli okunur', isCorrect: false },
      { text: 'Sesli (cehrî) olarak okunur', isCorrect: true },
      { text: 'Sessiz (sirrî) olarak okunur', isCorrect: false },
      { text: 'Cemaat sesli, imam sessiz okur', isCorrect: false },
    ],
  },
  {
    prompt: "Ramazan gecelerinde Kur'an'ın camilerde baştan sona okunmasına ne denir?",
    explanation:
      'Teravih namazlarında Kur\'an\'ın Ramazan boyunca hatimle tamamlanmasına "hatimle teravih" denir. Bu, camilerde yaygın bir uygulamadır.',
    difficulty: 2,
    options: [
      { text: 'Kadir kıyamı', isCorrect: false },
      { text: 'Mukabele orucu', isCorrect: false },
      { text: 'Sahur duası', isCorrect: false },
      { text: 'Hatimle teravih', isCorrect: true },
    ],
  },
  {
    prompt: 'Teravih namazını oturarak kılmak câiz midir?',
    explanation:
      'Teravih nafile olduğu için özürsüz de olsa oturarak kılınabilir; ancak ayakta kılmak daha faziletlidir. Farz namazlarda ise özür şarttır.',
    difficulty: 3,
    options: [
      { text: 'Yalnızca imam için câizdir', isCorrect: false },
      { text: 'Kesinlikle câiz değildir', isCorrect: false },
      { text: 'Câizdir, ancak ayakta kılmak daha faziletlidir', isCorrect: true },
      { text: 'Yalnızca son dört rekatta câizdir', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazına niyet nasıl edilir?',
    explanation:
      'Teravihe nafile namaz olarak niyet edilir; "teravih namazına" veya "vaktin sünnetine" şeklinde niyet etmek yeterlidir.',
    difficulty: 2,
    options: [
      { text: 'Nafile / teravih namazı olarak niyet edilir', isCorrect: true },
      { text: 'Yatsının farzı olarak niyet edilir', isCorrect: false },
      { text: 'Niyet gerekmez', isCorrect: false },
      { text: 'Kaza namazı olarak niyet edilir', isCorrect: false },
    ],
  },
  {
    prompt: 'Kadınlar teravih namazı kılar mı?',
    explanation:
      'Teravih kadın erkek her müslüman için sünnettir. Kadınlar evlerinde tek başına veya camide cemaatle kılabilirler.',
    difficulty: 1,
    options: [
      { text: 'Hayır, yalnızca erkeklere sünnettir', isCorrect: false },
      { text: 'Yalnızca imamın eşi kılabilir', isCorrect: false },
      { text: 'Evet, kadınlar için de sünnettir', isCorrect: true },
      { text: 'Yalnızca Kadir gecesinde kılabilirler', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazı ilk defa hangi dönemde düzenli cemaatle kılınmaya başlanmıştır?',
    explanation:
      'Hz. Peygamber teravihi birkaç gece cemaatle kıldırmış, farz olur endişesiyle bırakmıştır. Düzenli cemaatle kılınması Hz. Ömer döneminde tek imam arkasında toplanmasıyla yerleşmiştir.',
    difficulty: 3,
    options: [
      { text: 'Emevîler döneminde', isCorrect: false },
      { text: 'Osmanlı döneminde', isCorrect: false },
      { text: 'Abbasîler döneminde', isCorrect: false },
      { text: 'Hz. Ömer döneminde', isCorrect: true },
    ],
  },
  {
    prompt: 'Teravih namazı kaç rekatta bir selâm verilerek kılınır?',
    explanation:
      'Yaygın uygulamada teravih iki rekatta bir selâm verilerek kılınır. Dört rekatta bir selâm vermek de câiz görülmüştür.',
    difficulty: 2,
    options: [
      { text: 'Yirmi rekatın sonunda bir kez', isCorrect: false },
      { text: 'On rekatta bir', isCorrect: false },
      { text: 'Her rekattan sonra', isCorrect: false },
      { text: 'Genellikle iki rekatta bir', isCorrect: true },
    ],
  },
  {
    prompt: 'Teravih namazı orucun geçerliliğini etkiler mi?',
    explanation:
      'Teravih ile oruç birbirinden bağımsız ibadetlerdir. Teravih kılınmaması orucu geçersiz kılmaz; oruç kendi şartlarıyla geçerlidir.',
    difficulty: 1,
    options: [
      { text: 'Hayır, oruç ve teravih ayrı ibadetlerdir', isCorrect: true },
      { text: 'Yalnızca son on günde etkiler', isCorrect: false },
      { text: 'Evet, orucun kabulü teravihe bağlıdır', isCorrect: false },
      { text: 'Evet, teravih kılınmazsa oruç bozulur', isCorrect: false },
    ],
  },
  {
    prompt: "Ramazan'ın son on gecesinde aranması tavsiye edilen gece hangisidir?",
    explanation:
      "Kadir gecesinin Ramazan'ın son on gününün tek gecelerinde aranması tavsiye edilmiştir. Bu gecelerde ibadeti artırmak sünnettir.",
    difficulty: 2,
    options: [
      { text: 'Kadir gecesi', isCorrect: true },
      { text: 'Miraç gecesi', isCorrect: false },
      { text: 'Regaib gecesi', isCorrect: false },
      { text: 'Berat gecesi', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazında imama sonradan yetişen kişi ne yapar?',
    explanation:
      'İmama yetiştiği rekattan itibaren uyar; imam selâm verince yetişemediği rekatları tek başına tamamlar. Kalan rekatlar için cemaati beklemesi gerekmez.',
    difficulty: 2,
    options: [
      { text: 'Namaza hiç katılmaz', isCorrect: false },
      { text: 'İmama uyar, sonra eksik rekatları tamamlar', isCorrect: true },
      { text: 'Cemaatin bitmesini bekler', isCorrect: false },
      { text: 'Yirmi rekatı baştan tek başına kılar', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazının farz namazlara göre yeri nedir?',
    explanation:
      'Teravih nafile bir namazdır; farz namazların yerini tutmaz ve onların yerine geçmez. Farzlar her hâlükârda ayrıca kılınır.',
    difficulty: 1,
    options: [
      { text: 'Vitrin yerine geçer', isCorrect: false },
      { text: 'Yatsının farzının yerine geçer', isCorrect: false },
      { text: 'Nafiledir, farzların yerine geçmez', isCorrect: true },
      { text: 'O günün kazalarını düşürür', isCorrect: false },
    ],
  },
  {
    prompt: 'Teravih namazının adı hangi anlamdan gelmektedir?',
    explanation:
      '"Teravih", "tervîha" kelimesinin çoğuludur ve rahatlamak, dinlenmek anlamına gelir. Namazda dört rekatta bir verilen aralara işaret eder.',
    difficulty: 3,
    options: [
      { text: 'Dinlenmek, rahatlamak', isCorrect: true },
      { text: 'Sesli okumak', isCorrect: false },
      { text: 'Toplanmak, bir araya gelmek', isCorrect: false },
      { text: 'Gece yolculuğu yapmak', isCorrect: false },
    ],
  },
];
