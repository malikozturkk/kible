import { SeedPrayerQuestion } from '../seed-types';

export const JUMUAH_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Cuma namazının farzı kaç rekattır?',
    explanation:
      'Cuma namazının farzı iki rekattır ve cemaatle kılınır. Öncesinde ve sonrasında kılınan sünnetler bu iki rekata dâhil değildir.',
    difficulty: 1,
    options: [
      { text: '6 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: false },
      { text: '4 rekat', isCorrect: false },
      { text: '2 rekat', isCorrect: true },
    ],
  },
  {
    prompt: 'Cuma namazının farzından önce okunan konuşmaya ne ad verilir?',
    explanation:
      'İmamın minberde yaptığı konuşma hutbedir. Hutbe Cuma namazının şartlarındandır; hutbesiz kılınan Cuma geçerli olmaz.',
    difficulty: 1,
    options: [
      { text: 'Tesbihat', isCorrect: false },
      { text: 'Kamet', isCorrect: false },
      { text: 'Hutbe', isCorrect: true },
      { text: 'Kunut', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazının vakti hangi vakitle aynıdır?',
    explanation:
      'Cuma namazı öğle vaktinde kılınır; vakti güneşin zevalinden sonra başlar ve öğle vaktinin çıkmasıyla sona erer. O gün öğle namazının yerine geçer.',
    difficulty: 1,
    options: [
      { text: 'İkindi vakti', isCorrect: false },
      { text: 'Öğle vakti', isCorrect: true },
      { text: 'Kuşluk vakti', isCorrect: false },
      { text: 'Sabah vakti', isCorrect: false },
    ],
  },
  {
    prompt: 'Hutbe okunurken cemaatin nasıl davranması gerekir?',
    explanation:
      'Hutbe dinlenirken susmak ve dikkatle dinlemek gerekir. Konuşmak, başkasını uyarmak veya namaz kılmak hutbe esnasında hoş görülmemiştir.',
    difficulty: 1,
    options: [
      { text: 'Nafile namaz kılması gerekir', isCorrect: false },
      { text: 'Sesli olarak tekbir getirmesi gerekir', isCorrect: false },
      { text: 'Susup dikkatle dinlemesi gerekir', isCorrect: true },
      { text: "Kur'an okuması gerekir", isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazı kimlere farz-ı ayındır?',
    explanation:
      'Cuma namazı; akıllı, ergen, hür, mukim ve sağlıklı erkek müslümanlara farz-ı ayındır. Kadınlara, yolculara ve hastalara farz değildir; kılarlarsa geçerlidir.',
    difficulty: 2,
    options: [
      { text: 'Yalnızca yolculuktaki müslümanlara', isCorrect: false },
      { text: 'Sadece cami görevlisi olan kişilere', isCorrect: false },
      { text: 'Mukim, sağlıklı ve ergen erkek müslümanlara', isCorrect: true },
      { text: 'Ayırt etmeksizin bütün müslümanlara', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazını kılan bir erkek o gün ayrıca öğle namazı kılar mı?',
    explanation:
      'Cuma namazı o günün öğle namazının yerine geçer. Cumayı cemaatle kılan kişinin ayrıca öğle farzını kılması gerekmez.',
    difficulty: 1,
    options: [
      { text: 'Evet, ikisini de ayrı ayrı kılar', isCorrect: false },
      { text: 'Hayır, Cuma öğlenin yerine geçer', isCorrect: true },
      { text: 'Evet, ancak öğleyi iki rekat kılar', isCorrect: false },
      { text: 'Sadece hutbeyi kaçırmışsa kılar', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazına yetişemeyen kişi ne kılar?',
    explanation:
      'Cuma namazına yetişemeyen kişi o günün öğle namazını dört rekat farz olarak kılar. Cuma tek başına kaza edilmez.',
    difficulty: 2,
    options: [
      { text: 'Öğle namazını dört rekat olarak kılar', isCorrect: true },
      { text: "Ertesi Cuma'ya kaza bırakır", isCorrect: false },
      { text: 'Cuma namazını tek başına iki rekat kılar', isCorrect: false },
      { text: 'Hiçbir şey kılması gerekmez', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma günü için özellikle tavsiye edilen hazırlık nedir?',
    explanation:
      'Cuma günü gusletmek, temiz elbise giymek, güzel koku sürünmek ve camiye erken gitmek sünnettir.',
    difficulty: 1,
    options: [
      { text: 'Sabah namazından sonra oruç tutmak', isCorrect: false },
      { text: 'Hutbeden önce yemek yemek', isCorrect: false },
      { text: 'Öğleye kadar konuşmamak', isCorrect: false },
      { text: 'Gusledip temiz giyinmek ve erken gitmek', isCorrect: true },
    ],
  },
  {
    prompt: 'Cuma günü okunması tavsiye edilen sure hangisidir?',
    explanation:
      "Cuma günü Kehf suresini okumak hadislerde tavsiye edilmiştir. Ayrıca o gün Hz. Peygamber'e çokça salavat getirmek de sünnettir.",
    difficulty: 2,
    options: [
      { text: 'Tebbet suresi', isCorrect: false },
      { text: 'Nas suresi', isCorrect: false },
      { text: 'Bakara suresi', isCorrect: false },
      { text: 'Kehf suresi', isCorrect: true },
    ],
  },
  {
    prompt: 'Cuma namazının farzından sonra kaç rekat müekked sünnet kılınır (Hanefî)?',
    explanation:
      "Hanefîlerde Cuma'nın farzından sonra dört rekat müekked sünnet kılınır; bunun ardından iki rekat daha kılmak da yaygın uygulamadır.",
    difficulty: 2,
    options: [
      { text: 'Sünnet kılınmaz', isCorrect: false },
      { text: '4 rekat', isCorrect: true },
      { text: '6 rekat', isCorrect: false },
      { text: '2 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazının farzından önce kaç rekat sünnet kılınır (Hanefî)?',
    explanation:
      "Hanefîlerde Cuma'nın farzından önce dört rekat sünnet kılınır. Bu sünnet öğle namazının ilk sünnetine benzer şekilde eda edilir.",
    difficulty: 2,
    options: [
      { text: '4 rekat', isCorrect: true },
      { text: 'Sünnet kılınmaz', isCorrect: false },
      { text: '2 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazının farzında kıraat nasıl yapılır?',
    explanation:
      'Cuma namazı cehrî namazlardandır. İmam iki rekatın Fatiha ve zammı suresini cemaatin duyacağı şekilde sesli okur.',
    difficulty: 1,
    options: [
      { text: 'Cemaat sesli, imam sessiz okur', isCorrect: false },
      { text: 'Yalnızca Fatiha sesli okunur', isCorrect: false },
      { text: 'Sesli (cehrî) olarak okunur', isCorrect: true },
      { text: 'Sessiz (sirrî) olarak okunur', isCorrect: false },
    ],
  },
  {
    prompt: 'Camiye girildiğinde hutbe başlamışsa ne yapılır?',
    explanation:
      'Hutbe başlamışsa oturup dinlemek esastır. Hutbe sırasında nafile namaz kılmak ve konuşmak hoş görülmemiştir.',
    difficulty: 2,
    options: [
      { text: 'Dışarıda hutbenin bitmesi beklenir', isCorrect: false },
      { text: 'Sesli olarak selâm verilir', isCorrect: false },
      { text: 'Önce dört rekat sünnet kılınır', isCorrect: false },
      { text: 'Oturulup hutbe dinlenir', isCorrect: true },
    ],
  },
  {
    prompt: 'Cuma namazında imam hutbeyi nerede okur?',
    explanation:
      'İmam hutbeyi minberde ayakta okur. Hutbe iki bölüm hâlindedir ve arada kısa bir oturuşla ayrılır.',
    difficulty: 1,
    options: [
      { text: 'Cemaatin arasında yürüyerek okur', isCorrect: false },
      { text: 'Minberde ayakta okur', isCorrect: true },
      { text: 'Mihrapta oturarak okur', isCorrect: false },
      { text: 'Caminin avlusunda okur', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazı için gerekli olan cemaat şartı nedir (Hanefî)?',
    explanation:
      "Hanefîlere göre imamın dışında en az üç kişinin bulunması Cuma'nın sıhhati için yeterlidir. Belirli bir büyük sayı şart koşulmamıştır.",
    difficulty: 3,
    options: [
      { text: 'İmam dışında en az üç kişi bulunmalıdır', isCorrect: true },
      { text: 'Yalnızca cami görevlileri sayılır', isCorrect: false },
      { text: 'İmam dışında en az kırk kişi bulunmalıdır', isCorrect: false },
      { text: 'Cemaat şartı hiç aranmaz', isCorrect: false },
    ],
  },
  {
    prompt: 'Hutbenin iki bölümü arasında imam ne yapar?',
    explanation:
      'İmam birinci hutbeyi bitirince minberde kısa bir süre oturur, ardından ayağa kalkarak ikinci hutbeyi okur.',
    difficulty: 2,
    options: [
      { text: 'Mihraba geçip namaz kıldırır', isCorrect: false },
      { text: 'Cemaate soru sorar', isCorrect: false },
      { text: 'Kamet getirir', isCorrect: false },
      { text: 'Kısa bir süre oturur', isCorrect: true },
    ],
  },
  {
    prompt: 'Kadınların Cuma namazına gelmesi hakkında hüküm nedir?',
    explanation:
      'Cuma namazı kadınlara farz değildir; ancak camiye gelip cemaatle kılmaları câizdir ve kıldıkları takdirde o günün öğle namazı yerine geçer.',
    difficulty: 2,
    options: [
      { text: 'Farz değildir ama kılarlarsa geçerlidir', isCorrect: true },
      { text: 'Kıldıklarında ayrıca öğleyi de kılarlar', isCorrect: false },
      { text: 'Erkekler gibi farz-ı ayındır', isCorrect: false },
      { text: 'Kesinlikle kılmaları yasaktır', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazına imama son oturuşta yetişen kişi ne yapar?',
    explanation:
      "Hanefîlerde imama son oturuşta bile yetişen kişi Cuma'ya yetişmiş sayılır; imam selâm verdikten sonra kalkıp iki rekatı tamamlar.",
    difficulty: 3,
    options: [
      { text: "Cuma'ya yetişmiş sayılır, iki rekatı tamamlar", isCorrect: true },
      { text: "Cuma'yı kaçırmış sayılır, öğleyi kılar", isCorrect: false },
      { text: 'İmamla birlikte selâm verip bitirir', isCorrect: false },
      { text: 'Dört rekat farz kılması gerekir', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma günü camiye erken gitmenin fazileti nedir?',
    explanation:
      'Hadislerde camiye erken gidenin daha büyük sevap kazandığı, saf saf sıralanan meleklerin gelenleri kaydettiği bildirilmiştir.',
    difficulty: 2,
    options: [
      { text: 'Erken gidenin sünnetleri düşer', isCorrect: false },
      { text: 'Erken gitmenin ayrı bir fazileti yoktur', isCorrect: false },
      { text: 'Erken gidene daha büyük sevap bildirilmiştir', isCorrect: true },
      { text: 'Erken gitmek yalnızca imama tavsiye edilir', isCorrect: false },
    ],
  },
  {
    prompt: 'Cuma namazının sıhhati için hangi şart aranır?',
    explanation:
      'Cuma namazının sıhhati için vaktin girmesi, hutbenin okunması, cemaatin bulunması ve namazın herkese açık bir yerde kılınması aranır.',
    difficulty: 3,
    options: [
      { text: 'Yalnızca imamın resmî görevli olması', isCorrect: false },
      { text: 'Vakit, hutbe, cemaat ve umuma açıklık', isCorrect: true },
      { text: 'Yalnızca cemaatin gusletmiş olması', isCorrect: false },
      { text: 'Yalnızca caminin minareli olması', isCorrect: false },
    ],
  },
];
