import { SeedPrayerQuestion } from '../seed-types';

export const EID_ADHA_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Kurban Bayramı namazı kaç rekattır?',
    explanation:
      'Kurban Bayramı namazı da Ramazan Bayramı gibi iki rekattır ve cemaatle kılınır. Her rekatta zevâid tekbirleri alınır.',
    difficulty: 1,
    options: [
      { text: '2 rekat', isCorrect: true },
      { text: '3 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
      { text: '6 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı hangi ayın hangi gününde başlar?',
    explanation:
      'Kurban Bayramı, Zilhicce ayının onuncu günü başlar ve dört gün sürer. Hac ibadetinin de en yoğun günlerine denk gelir.',
    difficulty: 2,
    options: [
      { text: 'Zilhicce ayının 10. günü', isCorrect: true },
      { text: 'Şevval ayının 1. günü', isCorrect: false },
      { text: 'Recep ayının 27. günü', isCorrect: false },
      { text: 'Muharrem ayının 10. günü', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı sabahı namazdan önce yemek yemek hakkında sünnet nedir?',
    explanation:
      "Kurban Bayramı'nda namazdan önce bir şey yememek, kurban kesildikten sonra ilk olarak kurban etinden yemek sünnettir. Ramazan Bayramı'nda ise namazdan önce yemek sünnettir.",
    difficulty: 3,
    options: [
      { text: 'Namazdan önce oruç tutmak sünnettir', isCorrect: false },
      { text: 'Namazdan önce tatlı yemek sünnettir', isCorrect: false },
      { text: 'Bu konuda bir sünnet yoktur', isCorrect: false },
      { text: 'Namazdan önce yememek sünnettir', isCorrect: true },
    ],
  },
  {
    prompt: 'Kurban kesme vakti ne zaman başlar?',
    explanation:
      'Kurban, bayram namazı kılındıktan sonra kesilir. Namazdan önce kesilen hayvan kurban yerine geçmez, normal bir kesim sayılır.',
    difficulty: 2,
    options: [
      { text: 'Bayramın son günü öğleden sonra', isCorrect: false },
      { text: 'Bayram namazı kılındıktan sonra', isCorrect: true },
      { text: 'Bayram sabahı imsakla birlikte', isCorrect: false },
      { text: 'Arefe günü akşamı', isCorrect: false },
    ],
  },
  {
    prompt:
      'Arefe gününden bayramın dördüncü gününe kadar namazlardan sonra getirilen tekbire ne denir?',
    explanation:
      'Arefe günü sabah namazından bayramın dördüncü günü ikindi namazına kadar farzların ardından getirilen tekbire "teşrik tekbiri" denir.',
    difficulty: 2,
    options: [
      { text: 'İntikal tekbiri', isCorrect: false },
      { text: 'İftitah tekbiri', isCorrect: false },
      { text: 'Zevâid tekbiri', isCorrect: false },
      { text: 'Teşrik tekbiri', isCorrect: true },
    ],
  },
  {
    prompt: 'Teşrik tekbirleri hangi namazın ardından başlar?',
    explanation:
      'Teşrik tekbirleri arefe günü sabah namazının farzından sonra başlar ve bayramın dördüncü günü ikindi namazının farzıyla sona erer.',
    difficulty: 3,
    options: [
      { text: 'Bayramın birinci günü öğleden sonra', isCorrect: false },
      { text: 'Arefe günü sabah namazından sonra', isCorrect: true },
      { text: 'Arefe günü yatsı namazından sonra', isCorrect: false },
      { text: 'Bayram namazından hemen sonra', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı namazının vakti ne zamandır?',
    explanation:
      "Bayram namazının vakti güneşin doğup yükselmesiyle başlar, öğle vakti girmeden önce sona erer. Kurban Bayramı'nda erken kılınması tercih edilir.",
    difficulty: 1,
    options: [
      { text: 'İkindiden sonra', isCorrect: false },
      { text: 'Sabah ezanıyla birlikte', isCorrect: false },
      { text: 'Güneş yükseldikten sonra öğleden önce', isCorrect: true },
      { text: 'Öğle vaktinden sonra', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı namazında hutbe ne zaman okunur?',
    explanation:
      'Bayram namazlarında hutbe namazdan sonra okunur. Kurban Bayramı hutbesinde kurban ve teşrik tekbirleriyle ilgili hükümler hatırlatılır.',
    difficulty: 2,
    options: [
      { text: 'Bayram namazında hutbe yoktur', isCorrect: false },
      { text: 'Kurban kesildikten sonra okunur', isCorrect: false },
      { text: 'Namazdan önce okunur', isCorrect: false },
      { text: 'Namazdan sonra okunur', isCorrect: true },
    ],
  },
  {
    prompt: 'Kurban Bayramı namazı için ezan okunur mu?',
    explanation:
      'Bayram namazları için ezan ve kamet okunmaz. Cemaat toplandığında imam doğrudan namaza başlar.',
    difficulty: 2,
    options: [
      { text: 'Yalnızca kamet okunur', isCorrect: false },
      { text: 'Evet, ezan ve kamet okunur', isCorrect: false },
      { text: 'Hayır, ezan da kamet de okunmaz', isCorrect: true },
      { text: 'Yalnızca ezan okunur', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı namazının hükmü nedir (Hanefî)?',
    explanation:
      'Hanefî mezhebine göre bayram namazı, Cuma namazı kendisine farz olan kimselere vaciptir. Kurban Bayramı namazı için de aynı hüküm geçerlidir.',
    difficulty: 2,
    options: [
      { text: 'Vaciptir', isCorrect: true },
      { text: 'Farz-ı ayındır', isCorrect: false },
      { text: 'Sünnet-i gayr-i müekkededir', isCorrect: false },
      { text: 'Nafiledir', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı kaç gün sürer?',
    explanation:
      'Kurban Bayramı dört gün sürer; kurban kesimi de bayramın ilk üç gününde yapılabilir.',
    difficulty: 1,
    options: [
      { text: '7 gün', isCorrect: false },
      { text: '4 gün', isCorrect: true },
      { text: '3 gün', isCorrect: false },
      { text: '2 gün', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı namazında zevâid tekbirleri kaç tanedir (Hanefî)?',
    explanation:
      'Hanefî uygulamasında her rekatta üçer zevâid tekbiri alınır: birinci rekatta kıraatten önce, ikinci rekatta kıraatten sonra.',
    difficulty: 3,
    options: [
      { text: 'Her rekatta beşer tane', isCorrect: false },
      { text: 'Her rekatta üçer tane', isCorrect: true },
      { text: 'Yalnızca ikinci rekatta bir tane', isCorrect: false },
      { text: 'Yalnızca birinci rekatta yedi tane', isCorrect: false },
    ],
  },
  {
    prompt: "Kurban Bayramı'nda kesilen kurbanın eti nasıl değerlendirilir?",
    explanation:
      'Kurban eti; ev halkı, akraba ve komşularla ihtiyaç sahipleri arasında paylaştırılır. Üçe bölerek dağıtmak yaygın bir uygulamadır.',
    difficulty: 2,
    options: [
      { text: 'Aile, akraba ve ihtiyaç sahipleriyle paylaşılır', isCorrect: true },
      { text: 'Yalnızca kesen kişi tarafından tüketilir', isCorrect: false },
      { text: 'Tamamı satılarak parası dağıtılır', isCorrect: false },
      { text: 'Tamamı camiye teslim edilir', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazına giderken yol boyunca ne yapılması tavsiye edilir?',
    explanation:
      "Kurban Bayramı'nda namazgâha giderken tekbir getirmek sünnettir. Ramazan Bayramı'nda ise tekbirlerin sessiz getirilmesi tercih edilmiştir.",
    difficulty: 3,
    options: [
      { text: 'Tekbir getirmek', isCorrect: true },
      { text: "Kur'an okumak", isCorrect: false },
      { text: 'Ezan okumak', isCorrect: false },
      { text: 'Hiç konuşmamak', isCorrect: false },
    ],
  },
  {
    prompt: "Kurban Bayramı'nın ilk günü oruç tutulur mu?",
    explanation:
      "Kurban Bayramı'nın dört gününde de oruç tutmak yasaklanmıştır. Bu günler yeme, içme ve sevinç günleridir.",
    difficulty: 2,
    options: [
      { text: 'Yalnızca kurban kesmeyenler tutar', isCorrect: false },
      { text: 'Yalnızca namazdan önce tutulur', isCorrect: false },
      { text: 'Evet, ilk gün oruç tavsiye edilir', isCorrect: false },
      { text: 'Hayır, bayram günlerinde oruç tutulmaz', isCorrect: true },
    ],
  },
  {
    prompt: 'Kurban Bayramı namazına yetişemeyen kişi ne yapar?',
    explanation:
      'Bayram namazı cemaatle kılınır; kaçıran kişi tek başına kaza etmez. Aynı gün içinde başka bir cemaat bulursa onlarla kılabilir.',
    difficulty: 3,
    options: [
      { text: 'Yerine iki rekat vitir kılar', isCorrect: false },
      { text: 'Yerine dört rekat öğle namazı kılar', isCorrect: false },
      { text: 'Tek başına kaza etmez, başka cemaat arar', isCorrect: true },
      { text: 'Ertesi gün tek başına kaza eder', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı namazında kıraat nasıl yapılır?',
    explanation:
      'Bayram namazı cehrî kılınır; imam Fatiha ve zammı sureyi cemaatin duyacağı şekilde sesli okur.',
    difficulty: 2,
    options: [
      { text: 'Sessiz (sirrî) olarak okunur', isCorrect: false },
      { text: 'Sesli (cehrî) olarak okunur', isCorrect: true },
      { text: 'Cemaat sesli, imam sessiz okur', isCorrect: false },
      { text: 'Yalnızca ilk rekat sesli okunur', isCorrect: false },
    ],
  },
  {
    prompt: "Kurban Bayramı'ndan bir gün önceki güne ne ad verilir?",
    explanation:
      'Kurban Bayramı\'ndan önceki gün "arefe günü"dür. Hac ibadetinde Arafat vakfesi bu güne denk gelir ve teşrik tekbirleri bu gün başlar.',
    difficulty: 1,
    options: [
      { text: 'Berat gecesi', isCorrect: false },
      { text: 'Aşure günü', isCorrect: false },
      { text: 'Arefe günü', isCorrect: true },
      { text: 'Kadir gecesi', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban Bayramı namazına niyet nasıl edilir?',
    explanation:
      '"Kurban Bayramı namazına" diyerek kalben niyet edilir ve imama uyulur. Hangi bayram namazının kılındığını belirlemek yeterlidir.',
    difficulty: 2,
    options: [
      { text: 'Kaza namazına diye niyet edilir', isCorrect: false },
      { text: 'Niyet gerekmez', isCorrect: false },
      { text: 'Kurban Bayramı namazına diye niyet edilir', isCorrect: true },
      { text: 'Cuma namazına diye niyet edilir', isCorrect: false },
    ],
  },
  {
    prompt: 'Kurban ibadetinin temel amacı nedir?',
    explanation:
      "Kurban, Allah'a yakınlaşmayı ve teslimiyeti ifade eden bir ibadettir. Etin paylaşılmasıyla toplumsal dayanışmayı da güçlendirir.",
    difficulty: 1,
    options: [
      { text: 'Yalnızca borçları kapatmak', isCorrect: false },
      { text: 'Yalnızca et ihtiyacını karşılamak', isCorrect: false },
      { text: 'Yalnızca bir geleneği sürdürmek', isCorrect: false },
      { text: "Allah'a yakınlık ve teslimiyeti ifade etmek", isCorrect: true },
    ],
  },
];
