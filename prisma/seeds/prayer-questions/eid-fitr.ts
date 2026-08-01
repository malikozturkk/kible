import { SeedPrayerQuestion } from '../seed-types';

export const EID_FITR_QUESTIONS: SeedPrayerQuestion[] = [
  {
    prompt: 'Ramazan Bayramı namazı kaç rekattır?',
    explanation:
      'Bayram namazı iki rekattır ve cemaatle kılınır. Her iki rekatta fazladan tekbirler alınması yönüyle diğer namazlardan ayrılır.',
    difficulty: 1,
    options: [
      { text: '4 rekat', isCorrect: false },
      { text: '2 rekat', isCorrect: true },
      { text: '6 rekat', isCorrect: false },
      { text: '3 rekat', isCorrect: false },
    ],
  },
  {
    prompt: 'Ramazan Bayramı namazının vakti ne zamandır?',
    explanation:
      'Bayram namazının vakti güneşin doğup bir mızrak boyu yükselmesiyle başlar ve öğle vaktinin girmesinden önce sona erer.',
    difficulty: 1,
    options: [
      { text: 'Öğle vaktinden hemen sonra', isCorrect: false },
      { text: 'Sabah ezanıyla birlikte', isCorrect: false },
      { text: 'Güneş yükseldikten sonra öğleden önce', isCorrect: true },
      { text: 'İkindi ile akşam arasında', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazının hükmü nedir (Hanefî)?',
    explanation:
      'Hanefî mezhebine göre bayram namazı, Cuma namazı kendisine farz olan kimselere vaciptir.',
    difficulty: 2,
    options: [
      { text: 'Vaciptir', isCorrect: true },
      { text: 'Nafiledir', isCorrect: false },
      { text: 'Mekruhtur', isCorrect: false },
      { text: 'Farz-ı ayındır', isCorrect: false },
    ],
  },
  {
    prompt: 'Ramazan Bayramı sabahı namazdan önce yapılması tavsiye edilen nedir?',
    explanation:
      'Bayram sabahı gusledip temiz giyinmek, güzel koku sürünmek ve namaza gitmeden önce tatlı bir şey yemek sünnettir.',
    difficulty: 2,
    options: [
      { text: 'Namaza kadar konuşmamak', isCorrect: false },
      { text: 'Namaza kadar hiçbir şey yememek', isCorrect: false },
      { text: 'Namazdan önce oruç tutmak', isCorrect: false },
      { text: 'Gusledip tatlı bir şey yiyerek çıkmak', isCorrect: true },
    ],
  },
  {
    prompt: 'Bayram namazında hutbe ne zaman okunur?',
    explanation:
      'Bayram namazında hutbe namazdan sonra okunur. Cuma namazında ise hutbe namazdan önce okunur; bu iki namaz arasındaki temel farklardandır.',
    difficulty: 2,
    options: [
      { text: 'Namazdan önce okunur', isCorrect: false },
      { text: 'Namazdan sonra okunur', isCorrect: true },
      { text: 'Bayram namazında hutbe yoktur', isCorrect: false },
      { text: 'Rekatlar arasında okunur', isCorrect: false },
    ],
  },
  {
    prompt: 'Ramazan Bayramı namazından önce ödenmesi gereken sadaka hangisidir?',
    explanation:
      'Fitre (sadaka-i fıtır), bayram namazına çıkmadan önce verilmesi tavsiye edilen bir sadakadır; böylece ihtiyaç sahipleri de bayrama katılmış olur.',
    difficulty: 1,
    options: [
      { text: 'Fitre (sadaka-i fıtır)', isCorrect: true },
      { text: 'Kurban bedeli', isCorrect: false },
      { text: 'Keffâret', isCorrect: false },
      { text: 'Fidye', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazında her rekatta alınan fazladan tekbirlere ne denir?',
    explanation:
      'Bayram namazının her iki rekatında alınan fazladan üçer tekbire "zevâid tekbirleri" denir ve Hanefîlerde vaciptir.',
    difficulty: 3,
    options: [
      { text: 'İntikal tekbiri', isCorrect: false },
      { text: 'Zevâid tekbirleri', isCorrect: true },
      { text: 'İftitah tekbiri', isCorrect: false },
      { text: 'Teşrik tekbiri', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazında ezan ve kamet okunur mu?',
    explanation:
      'Bayram namazı için ezan ve kamet okunmaz. Cemaat toplandığında imam doğrudan namazı kıldırmaya başlar.',
    difficulty: 2,
    options: [
      { text: 'Evet, ikisi de okunur', isCorrect: false },
      { text: 'Yalnızca kamet okunur', isCorrect: false },
      { text: 'Hayır, ezan da kamet de okunmaz', isCorrect: true },
      { text: 'Yalnızca ezan okunur', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazına yetişemeyen kişi ne yapar?',
    explanation:
      'Bayram namazı cemaatle kılınan bir namazdır; kaçıran kişi tek başına kaza etmez. Aynı gün başka bir cemaat bulursa onlarla kılabilir.',
    difficulty: 3,
    options: [
      { text: 'Öğle namazını dört rekat kılar', isCorrect: false },
      { text: 'Ertesi gün tek başına kaza eder', isCorrect: false },
      { text: 'Yerine iki rekat vitir kılar', isCorrect: false },
      { text: 'Tek başına kaza etmez, başka cemaat arar', isCorrect: true },
    ],
  },
  {
    prompt: 'Ramazan Bayramı hangi ayın hangi gününde başlar?',
    explanation:
      'Ramazan Bayramı, Şevval ayının birinci günü başlar ve üç gün sürer. Ramazan orucunun tamamlanmasının ardından gelir.',
    difficulty: 2,
    options: [
      { text: 'Muharrem ayının 1. günü', isCorrect: false },
      { text: 'Zilhicce ayının 10. günü', isCorrect: false },
      { text: 'Şevval ayının 1. günü', isCorrect: true },
      { text: 'Ramazan ayının 30. günü', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazına giderken ve dönerken tavsiye edilen davranış nedir?',
    explanation:
      'Namazgâha bir yoldan gidip başka bir yoldan dönmek sünnettir. Yol boyunca tekbir getirmek de tavsiye edilmiştir.',
    difficulty: 3,
    options: [
      { text: 'Dönüşte oruç tutmaya başlamak', isCorrect: false },
      { text: 'Bir yoldan gidip başka yoldan dönmek', isCorrect: true },
      { text: 'Gidiş ve dönüşte hiç konuşmamak', isCorrect: false },
      { text: 'Namazgâha koşarak gitmek', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazının ikinci rekatında zevâid tekbirleri ne zaman alınır?',
    explanation:
      'İkinci rekatta kıraat tamamlandıktan sonra üç zevâid tekbiri alınır, ardından rükûa gidilir. İlk rekatta ise tekbirler kıraatten önce alınır.',
    difficulty: 3,
    options: [
      { text: 'Son oturuşta selâmdan önce', isCorrect: false },
      { text: 'Secdeler arasında', isCorrect: false },
      { text: "Kıraatten önce, Fatiha'dan hemen sonra", isCorrect: false },
      { text: 'Kıraatten sonra, rükûdan önce', isCorrect: true },
    ],
  },
  {
    prompt: 'Bayram günü oruç tutmak câiz midir?',
    explanation:
      "Ramazan Bayramı'nın birinci günü oruç tutmak yasaklanmıştır. O gün bayram sevincini paylaşmak ve yemek yemek esastır.",
    difficulty: 2,
    options: [
      { text: 'Evet, tutulması tavsiye edilir', isCorrect: false },
      { text: 'Yalnızca fitre verenler tutar', isCorrect: false },
      { text: 'Hayır, bayramın birinci günü oruç tutulmaz', isCorrect: true },
      { text: 'Yalnızca namazdan sonra tutulur', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazının kılınacağı açık alan meydanına ne ad verilir?',
    explanation:
      'Bayram namazının kılındığı açık alana "namazgâh" veya "musallâ" denir. Cemaatin çokluğu sebebiyle açık alanda kılınması sünnete uygundur.',
    difficulty: 3,
    options: [
      { text: 'Namazgâh (musallâ)', isCorrect: true },
      { text: 'Şadırvan', isCorrect: false },
      { text: 'Mihrap', isCorrect: false },
      { text: 'Minber', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazı için cemaat şartı var mıdır?',
    explanation:
      'Bayram namazı cemaatle kılınan bir namazdır; Cuma namazında olduğu gibi cemaat şartı aranır. Tek başına kılınmaz.',
    difficulty: 2,
    options: [
      { text: 'Hayır, tek başına da kılınabilir', isCorrect: false },
      { text: 'Evet, cemaatle kılınması şarttır', isCorrect: true },
      { text: 'Cemaat yalnızca hutbe için gereklidir', isCorrect: false },
      { text: 'Yalnızca kadınlar için cemaat şarttır', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram namazının hutbesini dinlemenin hükmü nedir?',
    explanation:
      'Bayram hutbesini dinlemek sünnettir. Cuma hutbesinden farklı olarak namazdan sonra okunduğu için hutbeyi dinlemeden ayrılmak namazı geçersiz kılmaz.',
    difficulty: 3,
    options: [
      { text: 'Farzdır; dinlenmezse namaz geçersizdir', isCorrect: false },
      { text: 'Mekruhtur; dinlenmemesi tavsiye edilir', isCorrect: false },
      { text: 'Yalnızca imam için geçerlidir', isCorrect: false },
      { text: 'Sünnettir; dinlenmemesi namazı bozmaz', isCorrect: true },
    ],
  },
  {
    prompt: 'Bayram namazına niyet nasıl edilir?',
    explanation:
      '"Ramazan Bayramı namazına" diyerek kalben niyet edilir ve imama uyulur. Niyette namazın hangi bayrama ait olduğunu belirlemek yeterlidir.',
    difficulty: 2,
    options: [
      { text: 'Ramazan Bayramı namazına diye niyet edilir', isCorrect: true },
      { text: 'Vitir namazına diye niyet edilir', isCorrect: false },
      { text: 'Niyet gerekmez', isCorrect: false },
      { text: 'Kaza namazına diye niyet edilir', isCorrect: false },
    ],
  },
  {
    prompt: 'Fitre kimlere verilir?',
    explanation:
      'Fitre, zekât verilebilecek ihtiyaç sahiplerine verilir. Amaç, bayram gününde ihtiyaç sahiplerinin de sevince ortak olmasıdır.',
    difficulty: 2,
    options: [
      { text: 'Yalnızca yolculara', isCorrect: false },
      { text: 'Yalnızca akrabalara', isCorrect: false },
      { text: 'Yalnızca cami görevlilerine', isCorrect: false },
      { text: 'Zekât verilebilecek ihtiyaç sahiplerine', isCorrect: true },
    ],
  },
  {
    prompt: 'Bayram namazında imama zevâid tekbirlerinden sonra yetişen kişi ne yapar?',
    explanation:
      'İmama uyar ve namazı onunla tamamlar; kaçırdığı zevâid tekbirlerini imam rükûa gitmeden yetişebiliyorsa alır, yetişemezse namaz geçerlidir.',
    difficulty: 3,
    options: [
      { text: 'Namaza hiç katılmaz', isCorrect: false },
      { text: 'Yalnızca hutbeyi dinler', isCorrect: false },
      { text: 'İmama uyar ve namazı onunla tamamlar', isCorrect: true },
      { text: 'Namazı baştan tek başına kılar', isCorrect: false },
    ],
  },
  {
    prompt: 'Bayram günü müslümanların birbirine yaptığı tebrikleşmenin amacı nedir?',
    explanation:
      'Bayramlaşmak, müslümanlar arasındaki bağı güçlendirmeyi, dargınlıkları gidermeyi ve sevinci paylaşmayı amaçlar; sünnete uygun bir davranıştır.',
    difficulty: 1,
    options: [
      { text: 'Bağları güçlendirip sevinci paylaşmak', isCorrect: true },
      { text: 'Fitrenin yerine geçmesini sağlamak', isCorrect: false },
      { text: 'Namazın eksiklerini tamamlamak', isCorrect: false },
      { text: 'Orucun kazasını düşürmek', isCorrect: false },
    ],
  },
];
