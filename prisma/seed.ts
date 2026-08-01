/**
 * Idempotent seed for the question banks.
 *
 *   yarn prisma:seed
 *
 * Every row gets a deterministic id (see `seedUuid`), so re-running upserts the
 * same rows instead of inserting duplicates. Rows not present in the seed data
 * are left untouched — nothing is deleted.
 */
import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrayerType, PrismaClient, QuestionScope } from '@prisma/client';
import { GUIDE_QUESTIONS } from './seeds/guide-questions';
import { PRAYER_QUESTION_GROUPS } from './seeds/prayer-questions';
import { SeedOption, seedUuid } from './seeds/seed-types';

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL environment variable is not set');
}

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString }),
  log: ['error'],
});

/**
 * Fails loudly on data problems the DB would otherwise swallow: a duplicate
 * prompt inside one pool would collapse two rows into one id and silently
 * shrink the pool.
 */
function validate(): void {
  const errors: string[] = [];
  const seenPrompts = new Set<string>();

  for (const group of PRAYER_QUESTION_GROUPS) {
    const scope = group.prayerType ?? 'GENERAL';
    for (const q of group.questions) {
      const key = `${scope}:${q.prompt}`;
      if (seenPrompts.has(key)) errors.push(`Duplicate prompt in ${scope}: ${q.prompt}`);
      seenPrompts.add(key);

      if (q.options.length < 2) errors.push(`Too few options: ${q.prompt}`);
      const correct = q.options.filter((o) => o.isCorrect).length;
      if (correct !== 1)
        errors.push(`Expected exactly 1 correct option (got ${correct}): ${q.prompt}`);
      if (!q.explanation.trim()) errors.push(`Empty explanation: ${q.prompt}`);
    }
  }

  const seenGuide = new Set<string>();
  for (const q of GUIDE_QUESTIONS) {
    const key = `${q.guideId}:${q.question}`;
    if (seenGuide.has(key)) errors.push(`Duplicate guide question in ${q.guideId}: ${q.question}`);
    seenGuide.add(key);

    if (!q.options.includes(q.correctAnswer)) {
      errors.push(`correctAnswer is not one of the options: ${q.question}`);
    }
  }

  if (errors.length > 0) {
    throw new Error(`Seed data is invalid:\n  - ${errors.join('\n  - ')}`);
  }
}

/**
 * Writes one `prayer_questions` row plus its options. Options are keyed by
 * `(questionId, orderIndex)`, which is what makes rows created by the
 * unify-question-bank migration (random option ids) upsert cleanly instead of
 * duplicating.
 */
async function upsertQuestion(args: {
  id: string;
  prompt: string;
  explanation: string | null;
  scope: QuestionScope;
  prayerType: PrayerType | null;
  guideId: string | null;
  difficulty: number;
  options: SeedOption[];
}): Promise<void> {
  const fields = {
    prompt: args.prompt,
    explanation: args.explanation,
    scope: args.scope,
    prayerType: args.prayerType,
    guideId: args.guideId,
    difficulty: args.difficulty,
    isActive: true,
  };

  await prisma.prayerQuestion.upsert({
    where: { id: args.id },
    create: { id: args.id, ...fields },
    update: fields,
  });

  for (const [orderIndex, option] of args.options.entries()) {
    await prisma.prayerQuestionOption.upsert({
      where: { questionId_orderIndex: { questionId: args.id, orderIndex } },
      create: {
        questionId: args.id,
        text: option.text,
        isCorrect: option.isCorrect,
        orderIndex,
      },
      update: { text: option.text, isCorrect: option.isCorrect },
    });
  }

  // Drop options left over from a previous, longer version of this question.
  await prisma.prayerQuestionOption.deleteMany({
    where: { questionId: args.id, orderIndex: { gte: args.options.length } },
  });
}

async function seedPrayerQuestions(): Promise<number> {
  let count = 0;

  for (const group of PRAYER_QUESTION_GROUPS) {
    const label = group.prayerType ?? 'GENERAL';

    for (const question of group.questions) {
      await upsertQuestion({
        id: seedUuid('prayer-question', label, question.prompt),
        prompt: question.prompt,
        explanation: question.explanation,
        scope: QuestionScope.PRAYER,
        prayerType: group.prayerType,
        guideId: null,
        difficulty: question.difficulty,
        options: question.options,
      });
      count += 1;
    }

    console.log(`  ${label.padEnd(9)} ${group.questions.length} soru`);
  }

  return count;
}

async function seedGuideQuestions(): Promise<number> {
  for (const question of GUIDE_QUESTIONS) {
    await upsertQuestion({
      // Same key as before the merge, so rows carried over by the migration match.
      id: seedUuid('guide-question', question.guideId, question.question),
      prompt: question.question,
      explanation: null,
      scope: QuestionScope.GUIDE,
      prayerType: null,
      guideId: question.guideId,
      difficulty: question.difficulty,
      options: question.options.map((text) => ({
        text,
        isCorrect: text === question.correctAnswer,
      })),
    });
  }
  return GUIDE_QUESTIONS.length;
}

async function main(): Promise<void> {
  validate();

  console.log('prayer_questions:');
  const prayerCount = await seedPrayerQuestions();

  const guideCount = await seedGuideQuestions();
  console.log(`questions (rehber): ${guideCount} soru`);

  console.log(`\nToplam ${prayerCount} namaz sorusu, ${guideCount} rehber sorusu yazıldı.`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => {
    void prisma.$disconnect();
  });
