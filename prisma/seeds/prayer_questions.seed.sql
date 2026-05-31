-- =====================================================================
-- Prayer Questions Seed
-- ---------------------------------------------------------------------
-- Targets the existing Prisma schema:
--   prayer_questions(id, prompt, explanation, "prayerType",
--                    difficulty, "isActive", "createdAt", "updatedAt")
--   prayer_question_options(id, "questionId", text, "isCorrect",
--                           "orderIndex", "createdAt")
--
-- XP is NOT stored on the question — it is awarded per prayer type by
-- PRAYER_XP_REWARDS in src/gamification/constants/prayer.constants.ts:
--   FAJR=20  DHUHR=15  ASR=15  MAGHRIB=15  ISHA=15
--   JUMUAH=25  TARAWIH=20  EID_FITR=50  EID_ADHA=50
--   + PRAYER_FIRST_OF_DAY_BONUS_XP = 10 (first prayer of the day)
--
-- Difficulty scale: 1=kolay, 2=orta, 3=zor.
--
-- Idempotency: run inside a transaction; re-running will create
-- duplicates because there is no unique constraint on `prompt`.
-- Run the cleanup block at the top if you want a clean reseed.
-- =====================================================================

BEGIN;

-- Required for gen_random_uuid() (already present on PG 13+).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Optional cleanup ────────────────────────────────────────────────
-- Uncomment to wipe the previously seeded set before re-inserting.
-- DELETE FROM prayer_question_options
--   WHERE "questionId" IN (SELECT id FROM prayer_questions);
-- DELETE FROM prayer_questions;

-- ── Helper: insert one question with N options as a single statement.
-- We use a WITH-INSERT-RETURNING pattern that keeps prompt + options
-- atomic and avoids a server-side variable.

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║                          FAJR  (2 farz)                          ║
-- ║  jahri kıraat • müekked 2 rk. sünnet öncesi • vakit: imsak→şuruk ║
-- ╚══════════════════════════════════════════════════════════════════╝

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah (fecir) namazının farzı kaç rekattır?',
    'Sabah namazının farzı 2 rekattır. Öncesinde 2 rekat müekked sünnet kılınır; toplamda 4 rekat olur.',
    'FAJR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('2 rekat',true,0),('3 rekat',false,1),('4 rekat',false,2),('1 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah namazının farzından önce kaç rekat sünnet kılınır?',
    'Fecir namazının öncesindeki 2 rekat sünnet, sünnetlerin en kuvvetlisi olarak değerlendirilir. Hz. Peygamberin seferde dahi bırakmadığı bilinen sünnetlerdendir.',
    'FAJR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('2 rekat',true,0),('4 rekat',false,1),('Sünnet yoktur',false,2),('1 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah namazının farzında kıraat (Fatiha ve zammı sure) nasıl yapılır?',
    'Sabah namazı cehrî (sesli) namazlardandır. İmam veya yalnız kılan kişi, ilk iki rekatın Fatiha ve zammı suresini cemaatin duyabileceği şekilde sesli okur.',
    'FAJR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Sesli (cehrî) olarak',true,0),('Sessiz (sirrî) olarak',false,1),('Sadece Fatiha sesli, zammı sure sessiz',false,2),('İmam sessiz, cemaat sesli okur',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah namazının vakti ne zaman sona erer?',
    'Sabah namazının vakti, fecr-i sâdıktan (imsak) güneşin doğmaya başladığı ana (şuruk) kadardır. Güneş ufukta görünmeye başladıktan sonra kılınması doğru değildir.',
    'FAJR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Güneş doğmaya başladığında',true,0),('Güneş tepe noktasına geldiğinde',false,1),('İkindi vakti girdiğinde',false,2),('Kuşluk vakti çıktığında',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah ezanında diğer ezanlardan farklı olarak okunan ek cümle nedir?',
    '"es-Salâtu hayrun mine''n-nevm" — "Namaz uykudan hayırlıdır" cümlesi yalnızca sabah ezanında, "hayye ale''l-felâh"tan sonra iki defa okunur.',
    'FAJR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('es-Salâtu hayrun mine''n-nevm',true,0),('Hayye alâ hayri''l-amel',false,1),('Lâ ilâhe illallâh (üç kez)',false,2),('Allâhümme bârik (ek olarak)',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Hanefî mezhebine göre sabah namazının farzında kunut duası okunur mu?',
    'Hanefî mezhebinde kunut yalnızca vitir namazında okunur. Şâfiî mezhebinde ise sabah namazının ikinci rekatının rükûsundan sonra kunut okunması sünnettir.',
    'FAJR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Okunmaz; kunut yalnız vitirdedir',true,0),('Her iki rekatta da okunur',false,1),('Sadece 1. rekatta okunur',false,2),('Sadece cemaatle kılınırken okunur',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah namazının farzı kaçırılırsa (kazaya kalırsa) ne yapılır?',
    'Hanefîlere göre o gün güneş tepe noktasına (zevâl) ulaşmadan önce sabah namazının farzı ile sünneti birlikte kaza edilir. Zevâlden sonra ise yalnız farzı kaza edilir, sünneti kaza edilmez.',
    'FAJR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Zevâle kadar farz ve sünnet birlikte kaza edilir',true,0),('Sadece sünneti kaza edilir',false,1),('Hiçbir şekilde kaza edilmez',false,2),('Ertesi gün sabah birlikte kılınır',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah namazının vakti hangi olayla başlar?',
    'Vakit, fecr-i sâdık dediğimiz, ufukta enine yayılan ikinci beyazlığın belirmesiyle başlar. Bu, imsak vaktidir; oruçlular için yeme-içmenin kesildiği andır.',
    'FAJR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Fecr-i sâdık (imsak)',true,0),('Güneşin doğması',false,1),('Şafakın kaybolması',false,2),('Güneşin bir mızrak boyu yükselmesi',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah namazının sünneti için tavsiye edilen kıraat hangisidir?',
    'Hz. Peygamberin sabah sünnetinin birinci rekatında Kâfirûn, ikinci rekatında İhlâs sûresini okuduğu rivayet edilmiştir.',
    'FAJR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('1. rekatta Kâfirûn, 2. rekatta İhlâs',true,0),('Sadece Fatiha okunur',false,1),('İki rekat Ayetel Kürsi',false,2),('1. rekatta Felak, 2. rekatta Nâs',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah namazından sonra güneş doğuncaya kadar nafile namaz kılmak nasıldır?',
    'Sabah farzından sonra güneşin doğmasına ve bir mızrak boyu yükselmesine kadar olan süre kerâhet vaktidir; bu vakit içinde nafile namaz kılmak mekruhtur.',
    'FAJR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Mekruhtur (kerâhet vakti)',true,0),('Müstehaptır',false,1),('Vaciptir',false,2),('Sadece tesbih namazı kılınabilir',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Sabah namazının farzı kaç oturuş içerir?',
    '2 rekatlı olduğu için yalnız son oturuş vardır. Burada Tahiyyât, Salli-Bârik ve dua okunur, ardından selam verilir.',
    'FAJR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('1 (son oturuş)',true,0),('2 (ara ve son oturuş)',false,1),('Oturuş yoktur',false,2),('3 oturuş',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Cemaatle sabah namazı kılınırken cemaat Fatiha''yı nasıl okur (Hanefî)?',
    'Hanefîlere göre cehrî namazlarda cemaat hiçbir şey okumaz; imamın kıraati cemaat için de yeterlidir. Cemaat yalnız susarak dinler.',
    'FAJR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Okumaz; susarak imamı dinler',true,0),('İmamla birlikte sesli okur',false,1),('Sadece içinden Fatiha okur',false,2),('Sadece zammı sureyi okur',false,3)) AS t(text,ok,idx);


-- ╔══════════════════════════════════════════════════════════════════╗
-- ║                       DHUHR  (Öğle, 4 farz)                      ║
-- ║  sirrî kıraat • 4 sünnet + 4 farz + 2 sünnet = 10 rk             ║
-- ╚══════════════════════════════════════════════════════════════════╝

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle namazının farzı kaç rekattır?',
    'Öğle namazının farzı 4 rekattır; sirrî (sessiz) okunur. Tüm dört rekatta da Fatiha okunur, ilk iki rekatta ayrıca zammı sure eklenir.',
    'DHUHR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('4 rekat',true,0),('2 rekat',false,1),('3 rekat',false,2),('6 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle namazı sünnetler dahil toplam kaç rekattır?',
    'Öğle: 4 ilk sünnet (müekked) + 4 farz + 2 son sünnet (müekked) = 10 rekat. Cuma günleri farz yerine Cuma namazı kılınır.',
    'DHUHR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('10 rekat (4+4+2)',true,0),('8 rekat',false,1),('12 rekat',false,2),('4 rekat (sadece farz)',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle namazının kıraati nasıl yapılır?',
    'Öğle namazı sirrî (sessiz) namazlardandır. İmam dahi farzda Fatiha ve sureyi içinden okur; ses çıkarmaz.',
    'DHUHR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Sessiz (sirrî)',true,0),('Sesli (cehrî)',false,1),('İlk iki rekat sesli, son iki rekat sessiz',false,2),('İmam sesli, münferid sessiz',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle vakti ne zaman başlar?',
    'Öğle vakti, güneşin tam tepe noktasından (istivâ) batıya doğru kaymaya başlamasıyla (zevâl) girer.',
    'DHUHR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Güneşin zevâlden batıya kayması ile',true,0),('Güneşin doğuşu ile',false,1),('Kuşluk vaktinin sonunda',false,2),('Eşyanın gölgesi kendisinin iki katı olunca',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle vakti ne zaman çıkar?',
    'Hanefîlerde imâmeyn (Ebû Yûsuf ve Muhammed) görüşüne göre öğle vakti, her şeyin gölgesi kendisi kadar oluncaya kadardır; bu görüş fetvada esastır.',
    'DHUHR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Eşyanın gölgesi kendisi kadar olunca',true,0),('Güneş batınca',false,1),('Güneş tam tepedeyken',false,2),('İmsak vakti ile birlikte',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle namazının farzından önce kaç rekat sünnet kılınır?',
    'Öğlenin ilk sünneti 4 rekat olup müekked sünnetlerdendir. Tek selamla, iki oturuşla kılınır.',
    'DHUHR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('4 rekat',true,0),('2 rekat',false,1),('6 rekat',false,2),('Sünnet yoktur',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle namazının farzından sonra kaç rekat sünnet kılınır?',
    'Farzdan sonra kılınan 2 rekat son sünnet de müekkeddir. Bazıları buna ek 2 rekat daha gayri müekked sünnet kılar.',
    'DHUHR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('2 rekat',true,0),('4 rekat',false,1),('Sünnet yoktur',false,2),('1 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Cuma günü cemaatle Cuma namazı kılan bir erkek ayrıca öğle namazı kılar mı?',
    'Cuma namazı kendisine farz olan kişiye Cuma kılındığında öğle farzını ayrıca kılmaz; Cuma namazı öğle farzının yerine geçer.',
    'DHUHR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Hayır; Cuma öğlenin yerine geçer',true,0),('Evet, ayrıca 4 rekat farz kılar',false,1),('Sadece 2 rekat kılar',false,2),('Önce öğle sonra Cuma kılar',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle namazının farzında 3. ve 4. rekatlarda Fatiha''dan sonra zammı sure okunur mu?',
    'Hanefîlerde farzın 3. ve 4. rekatlarında yalnız Fatiha okunur; zammı sure okunmaz. İlk iki rekatta ise Fatiha + zammı sure okunması vaciptir.',
    'DHUHR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Okunmaz; sadece Fatiha okunur',true,0),('Okunur; her rekatta Fatiha + sure',false,1),('Sadece 4. rekatta okunur',false,2),('Sadece Ayetel Kürsi okunur',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğlenin ilk 4 rekat sünnetinde iki rekatta bir Tahiyyât için oturulur mu?',
    'Öğlenin ilk sünneti dört rekat tek selâmla kılınır. İki rekat sonunda yalnız Tahiyyât okunur; Salli-Bârik okunmaz, ayağa kalkılır ve 3-4. rekatta hem Fatiha hem zammı sure okunur.',
    'DHUHR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Evet; Tahiyyât okunur, ardından kalkılır',true,0),('Hayır; oturuş yapılmaz',false,1),('Evet; Tahiyyât + Salli-Bârik okunur',false,2),('Hayır; selam verilir, sünnet sonlanır',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Öğle namazının son sünneti (2 rekat) terkedilirse farz geçerli olur mu?',
    'Sünnetin terki farzı bozmaz; namaz geçerlidir. Ancak müekked sünnet terk edildiğinden sevap eksilir; düzenli terki mekruh olur.',
    'DHUHR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Evet; farz geçerlidir, sevap eksilir',true,0),('Hayır; farz da iade edilmelidir',false,1),('Sadece imam için geçerlidir',false,2),('Hayır; tek başına farz olmaz',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Yolcu (seferî) bir kişi öğle namazının farzını kaç rekat kılar?',
    'Seferîlik şartlarını taşıyan kişi öğle, ikindi ve yatsı farzlarını 2 rekat olarak (kasr ederek) kılar. Sünnetler kişinin tercihine bağlıdır, terki günah değildir.',
    'DHUHR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('2 rekat (kasr)',true,0),('4 rekat (tam)',false,1),('3 rekat',false,2),('Düşer; kılınmaz',false,3)) AS t(text,ok,idx);


-- ╔══════════════════════════════════════════════════════════════════╗
-- ║                       ASR  (İkindi, 4 farz)                      ║
-- ║  sirrî • 4 gayri-müekked sünnet + 4 farz = 8 rk                  ║
-- ╚══════════════════════════════════════════════════════════════════╝

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'İkindi namazının farzı kaç rekattır?',
    'İkindinin farzı 4 rekat olup sirrî olarak kılınır. Öncesindeki 4 rekat sünnet gayri müekkeddir; ikindi farzından sonra sünnet kılınmaz.',
    'ASR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('4 rekat',true,0),('2 rekat',false,1),('3 rekat',false,2),('6 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'İkindi namazından sonra kaç rekat sünnet kılınır?',
    'İkindi farzından sonra sünnet kılınmaz. Bu vakit, güneş batıncaya kadar nafile namaz için mekruh sayılır.',
    'ASR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Sünnet kılınmaz',true,0),('2 rekat',false,1),('4 rekat',false,2),('6 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'İkindi namazının kıraati nasıl yapılır?',
    'İkindi namazı sirrî (sessiz) namazlardandır. Cemaatle de münferid de Fatiha ve zammı sure içten okunur.',
    'ASR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Sessiz (sirrî)',true,0),('Sesli (cehrî)',false,1),('Sadece ilk rekatta sesli',false,2),('İmam sesli, cemaat sessiz',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'İkindi vakti, öğle vakti çıktıktan sonra başlar ve ne zaman sona erer?',
    'İkindi vakti, öğle vaktinin çıkışıyla başlar ve güneş batıncaya kadar sürer.',
    'ASR', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Güneş batıncaya kadar',true,0),('Güneşin tepeye ulaşmasına kadar',false,1),('Yatsı vakti girene kadar',false,2),('Fecre kadar',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Güneşin batmaya yaklaştığı, ışığının zayıflayıp sararıp kızarmaya başladığı vakitte ikindiyi kılmak nasıldır?',
    'Bu vakte "ısfirar" denir ve mekruh vakittir. İkindiyi kasıtlı olarak bu vakte bırakmak doğru değildir; o günün ikindisini bu vakitte ancak iade etmeden kılan kişinin namazı sahihtir fakat tahrîmen mekruh olur.',
    'ASR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Mekruhtur, ancak o günün ikindisi sahih kılınmış olur',true,0),('Müstehaptır',false,1),('Tamamen geçersizdir',false,2),('Vacip kılan vakittir',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'İkindi vakti girmeden kılınan "ikindi" namazı geçerli olur mu?',
    'Vakit girmeden farz namaz sahih olmaz. Vakitten önce kılınan ikindi farzı geçersizdir; vakit girince iade edilmesi gerekir.',
    'ASR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Geçersizdir; iade edilmelidir',true,0),('Geçerlidir; sevap eksilir',false,1),('Sadece cemaatle geçerlidir',false,2),('Niyet doğruysa geçerlidir',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Hanefîlerde ikindinin sünneti müekked midir?',
    'İkindinin ilk 4 rekat sünneti gayri müekkeddir. Hz. Peygamberin devamlı kıldığı sünnetlerden olmadığı için terki günah değildir, ancak kılınması faziletlidir.',
    'ASR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Gayri müekked sünnettir',true,0),('Müekked sünnettir',false,1),('Vaciptir',false,2),('Bid''attir',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Bir kimse ikindi farzına 1. rekatın rükûunda yetişirse o rekatı imamla birlikte kılmış sayılır mı?',
    'İmama rükûda yetişen kişi o rekata yetişmiş sayılır. Bu, ikindi de dahil tüm namazlarda geçerli olan genel bir kuraldır.',
    'ASR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Evet; rükûya yetişen rekata yetişmiştir',true,0),('Hayır; sadece kıyâma yetişen sayılır',false,1),('Sadece tekbir alıp Fatiha okuyana yetişen sayılır',false,2),('Sadece imamla birlikte selâm verene yetişmiş sayılır',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'İkindiden sonra cenaze namazı kılınabilir mi?',
    'İkindi sonrasında, güneşin ısfirar vakti dışında, cenaze namazı kılınabilir. Cenaze namazı vakti müsait olduğu sürece kerâhet vakitleri dışında geciktirilmez.',
    'ASR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Kerâhet vakti dışında kılınabilir',true,0),('Hiçbir şekilde kılınamaz',false,1),('Sadece imamlı ise kılınır',false,2),('Sadece kadınlar kılar',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    '"Salâtu''l-vustâ" (orta namaz) Kur''an''da hangi namaz için kullanılmıştır (yaygın görüş)?',
    'Bakara 238. ayette geçen "salâtu''l-vustâ" hakkında en kuvvetli rivayet ikindi namazına işaret ettiği yönündedir. Hz. Peygamber Hendek günü "salâtu''l-vustâ olan ikindi"den söz etmiştir.',
    'ASR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('İkindi (asr) namazı',true,0),('Öğle (zuhr) namazı',false,1),('Akşam namazı',false,2),('Vitir namazı',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'İkindi farzında ilk iki rekattan sonra Tahiyyât için oturulur; bu oturuş namazın hangi unsurudur?',
    'Dört rekatlı farzlardaki ara oturuş "kâde-i ûlâ"dır ve vaciptir. Burada yalnız Tahiyyât okunur; unutularak terki sehiv secdesini gerektirir.',
    'ASR', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Vacip olan kâde-i ûlâ',true,0),('Müstehap olan kâde-i ûlâ',false,1),('Farz olan kâde-i ahîre',false,2),('Mubah bir oturuştur',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Vakti içinde ikindiyi kılamayıp güneş batan kişinin durumu nedir?',
    'Vakit çıktıktan sonra namaz kazaya kalır. Sahibi, kazasını kerâhet vakitlerinin dışında ilk fırsatta eda eder; tertip sahibi ise sıraya riayet eder.',
    'ASR', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Kaza eder',true,0),('Düşer; sorumluluğu kalkar',false,1),('Sadece sünneti kaza eder',false,2),('Yatsı ile birleştirir',false,3)) AS t(text,ok,idx);


-- ╔══════════════════════════════════════════════════════════════════╗
-- ║                     MAGHRIB  (Akşam, 3 farz)                     ║
-- ║  ilk 2 rk cehrî, 3. rk sirrî • 3 farz + 2 müekked sünnet = 5 rk  ║
-- ╚══════════════════════════════════════════════════════════════════╝

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam namazının farzı kaç rekattır?',
    'Akşam farzı 3 rekattır ve gündüzün vitri olarak nitelenir. Tek rekatlı olması bakımından beş vakit içinde tektir.',
    'MAGHRIB', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('3 rekat',true,0),('2 rekat',false,1),('4 rekat',false,2),('5 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam namazı sünnet dahil toplam kaç rekattır?',
    'Akşam: 3 farz + 2 son sünnet (müekked) = 5 rekat. Öncesinde farz olarak nitelenmiş bir sünnet yoktur.',
    'MAGHRIB', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('5 rekat (3+2)',true,0),('7 rekat (3+4)',false,1),('3 rekat (yalnız farz)',false,2),('9 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam farzının kıraati nasıl yapılır?',
    'Akşam farzının ilk iki rekatı cehrî (sesli), üçüncü rekatı ise sirrî (sessiz) okunur. 3. rekatta yalnız Fatiha okunur, zammı sure eklenmez.',
    'MAGHRIB', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('İlk 2 rekat sesli, 3. rekat sessiz',true,0),('Tamamı sessiz',false,1),('Tamamı sesli',false,2),('Sadece son rekat sesli',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam vakti ne zaman başlar?',
    'Akşam vakti, güneşin batmasıyla başlar. İftar vakti ile aynı andır.',
    'MAGHRIB', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Güneşin batmasıyla',true,0),('Şafakın kaybolmasıyla',false,1),('Güneşin sararmasıyla',false,2),('Yıldızların görünmesiyle',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam vakti ne zaman çıkar?',
    'Akşam vakti, batı ufkundaki şafağın (kırmızılığın, Ebû Hanîfe''ye göre beyazlığın) kaybolmasıyla biter ve yatsı vakti başlar.',
    'MAGHRIB', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Şafak (kızıllık/beyazlık) kayboluncaya kadar',true,0),('Yatsı ezanına 30 dk kala',false,1),('Güneşin doğmasıyla',false,2),('Bir saat sonra',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam namazının farzında 3. rekatta Fatiha''dan sonra zammı sure okunur mu?',
    'Akşamın 3. rekatında yalnız Fatiha okunur. Öğle/ikindi/yatsının 3-4. rekatlarındaki uygulama gibi, zammı sure eklenmez.',
    'MAGHRIB', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Okunmaz; yalnız Fatiha okunur',true,0),('Kısa bir sure okunur',false,1),('Ayetel Kürsi okunur',false,2),('İhlâs okunması vaciptir',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam namazını sebepsiz geciktirmek nasıldır?',
    'Akşam namazını yıldızlar görünene veya gecenin ileri saatlerine bırakmak mekruhtur. Vakit girer girmez kısa sürede kılınması müstehaptır.',
    'MAGHRIB', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Mekruhtur',true,0),('Müstehaptır',false,1),('Vaciptir',false,2),('Fazileti artırır',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşamın son sünneti 2 rekat olarak nasıl kılınır?',
    'Tek selamla iki rekat halinde kılınır; ilk rekatta Fatiha + zammı sure, son oturuşta Tahiyyât + Salli-Bârik + dua okunarak selâm verilir.',
    'MAGHRIB', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Tek selamla, iki rekat olarak',true,0),('Dört rekat tek selâmla',false,1),('Her rekatta selâm verilerek',false,2),('Üç rekat tek selâm ile',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam namazında kaç oturuş bulunur?',
    '3 rekatlı olduğu için 2 oturuş vardır: 2. rekatın sonundaki kâde-i ûlâ (vacip) ile 3. rekatın sonundaki kâde-i ahîre (farz).',
    'MAGHRIB', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('2 oturuş',true,0),('1 oturuş',false,1),('3 oturuş',false,2),('Oturuş yoktur',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam namazına imama 3. rekatta yetişen kişi, imam selâm verdikten sonra kaçar rekat tek başına tamamlar?',
    'İmama 3. rekatta yetişen kişi imamla birlikte selâm vermez; kalkıp eksik 2 rekatı, Fatiha + zammı sure okuyarak iki rekat olarak tamamlar.',
    'MAGHRIB', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('2 rekat (her ikisinde Fatiha + zammı sure)',true,0),('1 rekat (yalnız Fatiha)',false,1),('3 rekat (her birinde Fatiha)',false,2),('Hiç; imamla selâm verir',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Seferî olan kişi akşam namazının farzını kaç rekat kılar?',
    'Akşam, sabah ve vitir namazları seferî olsa dahi kasr edilmez; akşam yine 3 rekat olarak kılınır.',
    'MAGHRIB', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('3 rekat (kasr edilmez)',true,0),('2 rekat',false,1),('4 rekat',false,2),('1 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Akşam namazından sonra "evvâbîn namazı" olarak kılınabilecek nafile kaç rekattır?',
    'Akşam farz ve müekked sünnetinden sonra kılınan, hadislerde teşvik edilen 6 rekatlık nafile namaz "evvâbîn" olarak isimlendirilir.',
    'MAGHRIB', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('6 rekat',true,0),('4 rekat',false,1),('2 rekat',false,2),('8 rekat',false,3)) AS t(text,ok,idx);


-- ╔══════════════════════════════════════════════════════════════════╗
-- ║                       ISHA  (Yatsı, 4 farz)                      ║
-- ║  ilk 2 rk cehrî, son 2 rk sirrî • 4+4+2 + vitir(3 vacib) = 13 rk ║
-- ╚══════════════════════════════════════════════════════════════════╝

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Yatsı namazının farzı kaç rekattır?',
    'Yatsı farzı 4 rekattır. İlk iki rekat cehrî, son iki rekat ise sirrî okunur (öğle ve ikindiden farkı buradadır).',
    'ISHA', 1, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('4 rekat',true,0),('2 rekat',false,1),('3 rekat',false,2),('6 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Yatsı farzının kıraati nasıl yapılır?',
    'Yatsı farzının ilk iki rekatı cehrî (sesli), son iki rekatı ise sirrî (sessiz) okunur. Sabah ve akşam ile birlikte cehrî namazlardandır.',
    'ISHA', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('İlk 2 rekat sesli, son 2 rekat sessiz',true,0),('Tamamı sessiz',false,1),('Tamamı sesli',false,2),('Sadece son rekat sesli',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Hanefî mezhebinde vitir namazının hükmü nedir?',
    'Hanefîlere göre vitir vaciptir. Yatsı vakti içinde, yatsının farzından sonra kılınır. 3 rekat olup son rekatta zammı sureden sonra tekbir alınıp Kunut duası okunur.',
    'ISHA', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Vaciptir',true,0),('Sünnettir',false,1),('Müstehaptır',false,2),('Farzdır',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Vitir namazı kaç rekattır (Hanefî)?',
    'Hanefîde vitir 3 rekat tek selâmla kılınır; 2. rekat sonunda oturulup yalnız Tahiyyât okunur, 3. rekatta Fatiha + zammı sure ardından kunut yapılır.',
    'ISHA', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('3 rekat',true,0),('1 rekat',false,1),('2 rekat',false,2),('5 rekat',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Yatsı vakti ne zaman başlar?',
    'Yatsı vakti, batı ufkunda akşamın şafağının (kızıllık/beyazlık) kaybolmasıyla başlar ve ikinci fecre (imsak) kadar sürer.',
    'ISHA', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Şafak kaybolunca',true,0),('Güneş batar batmaz',false,1),('Gece yarısı',false,2),('İmsakla birlikte',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Vitir namazını yatsıdan önce kılmak câiz midir?',
    'Vitir, yatsı farzı kılındıktan sonra kılınır. Yatsının farzı kılınmadan önce vitir kılınmaz; aksi halde yatsı kılındıktan sonra vitri iade etmek gerekir.',
    'ISHA', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Hayır; yatsı farzından sonra kılınır',true,0),('Evet, her zaman câizdir',false,1),('Sadece seferî için câizdir',false,2),('Sadece Ramazan''da câizdir',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Vitir namazının kazası gerekir mi?',
    'Vitir vacip olduğu için kazaya kalırsa kaza edilmesi gerekir. Sabah uyanan kişi, kerâhet vakti dışında vitri kaza eder.',
    'ISHA', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Evet; vacip olduğu için kazası lazımdır',true,0),('Hayır; sünnet olduğu için kazası yoktur',false,1),('Sadece üç gün içinde kaza edilir',false,2),('Yalnız Cuma günü kaza edilir',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Yatsı namazının ilk sünneti (4 rekat) hangi sünnet türündendir?',
    'Yatsının ilk 4 rekat sünneti gayri müekkeddir; son sünneti olan 2 rekat ise müekkeddir.',
    'ISHA', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Gayri müekked sünnet',true,0),('Müekked sünnet',false,1),('Vacip',false,2),('Farz-ı kifâye',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Teravih namazı hangi vakitte kılınır?',
    'Teravih yalnız Ramazan ayında, yatsı namazından sonra ve vitir namazından önce (veya sonrasında) kılınır. Yatsının farzı kılınmadan teravih kılınmaz.',
    'ISHA', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Yatsı farzından sonra',true,0),('Yatsı farzından önce',false,1),('Akşamla yatsı arası, yatsıdan önce',false,2),('Vitirden sonra fecre kadar her vakit',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Hanefîye göre yatsı vaktinin en faziletli kılınma vakti hangisidir?',
    'Hanefîlere göre yatsı namazını gecenin üçte birine kadar geciktirmek müstehaptır. Gece yarısından sonraya bırakmak ise mekruhtur.',
    'ISHA', 3, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Gecenin ilk üçte birine kadar geciktirmek',true,0),('Vakit girer girmez kılmak müekkeddir',false,1),('Gece yarısından sonraya bırakmak',false,2),('Sabaha yakın kılmak',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Vitir namazının 3. rekatında okunan dua hangisidir?',
    '3. rekatta zammı sureden sonra eller kulak hizasına kaldırılıp tekbir alınır, ardından bağlanır ve "Allâhümme innâ neste''înüke..." ile başlayan kunut duası okunur.',
    'ISHA', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Kunut duası',true,0),('Salli-Bârik',false,1),('Rabbenâ âtinâ',false,2),('Tahiyyât',false,3)) AS t(text,ok,idx);

WITH q AS (
  INSERT INTO prayer_questions (id, prompt, explanation, "prayerType", difficulty, "isActive", "updatedAt")
  VALUES (gen_random_uuid(),
    'Yatsı vakti içinde uyuyakalıp namazı kaçıran kişi sabah uyandığında ne yapar?',
    'Vakit çıktığı için yatsı farzını ve vitri kerâhet vakti dışında ilk fırsatta kaza eder. Tertip sahibi ise kazaya bıraktığı namazları sıraya göre kılar.',
    'ISHA', 2, true, NOW())
  RETURNING id)
INSERT INTO prayer_question_options (id, "questionId", text, "isCorrect", "orderIndex")
SELECT gen_random_uuid(), q.id, t.text, t.ok, t.idx FROM q,
  (VALUES ('Hem yatsıyı hem vitri kaza eder',true,0),('Sadece yatsıyı kaza eder; vitir düşer',false,1),('Vitri sabaha katar, yatsı düşer',false,2),('Hiçbir şey yapmaz; sevabı umulur',false,3)) AS t(text,ok,idx);

COMMIT;

-- =====================================================================
-- Sanity check
-- =====================================================================
-- SELECT "prayerType", COUNT(*) FROM prayer_questions
--   WHERE "isActive" = true
--   GROUP BY "prayerType" ORDER BY 1;
-- Expected (after this seed):
--   FAJR    | 12
--   DHUHR   | 12
--   ASR     | 12
--   MAGHRIB | 12
--   ISHA    | 12
