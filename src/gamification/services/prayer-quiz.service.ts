import { HttpStatus, Injectable } from '@nestjs/common';
import { Prisma, PrayerQuestion, PrayerType } from '@prisma/client';
import { DateTime } from 'luxon';
import { PrismaService } from '../../prisma/prisma.service';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LocalDate } from '../../common/utils/local-date';
import { PrayerSlot, PrayerScheduleParams } from '../types/gamification.types';
import {
  PRAYER_QUIZ_EXPIRY_GRACE_MINUTES,
  PRAYER_QUIZ_QUESTION_COUNT,
} from '../constants/prayer.constants';
import { isWithinWindow } from '../helpers/prayer-schedule.helper';
import { PrayerScheduleService } from './prayer-schedule.service';
import { PrayerQuestionsResponseDto, QuestionPublicDto } from '../dto/prayer-questions.dto';
import { QuizAnswerDto } from '../dto/gamification-action.dto';

@Injectable()
export class PrayerQuizService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly scheduleService: PrayerScheduleService,
  ) {}

  async issueQuiz(
    params: PrayerScheduleParams,
    prayerType: PrayerType,
  ): Promise<PrayerQuestionsResponseDto> {
    const { userId, timezone } = params;
    const { slot, zonedDate } = this.scheduleService.resolveSlot(params, prayerType);
    const now = DateTime.now().setZone(timezone);

    this.assertWindowOpen(slot, now);
    await this.assertNotAlreadyCompleted(userId, slot, zonedDate, timezone);
    const prayerDate = LocalDate.fromInstant(zonedDate, timezone);
    const existing = await this.prisma.prayerQuizSubmission.findFirst({
      where: {
        userId,
        prayerType,
        prayerDate: prayerDate.toUtcMidnight(),
        status: 'PENDING',
        expiresAt: { gt: new Date() },
      },
    });

    if (existing) {
      const questions = await this.loadQuestionsForSubmission(existing.questionIds);
      return {
        quizId: existing.id,
        expiresAt: existing.expiresAt.toISOString(),
        questions,
      };
    }

    const pool: Array<{ id: string }> = await this.prisma.prayerQuestion.findMany({
      where: {
        isActive: true,
        OR: [{ prayerType: null }, { prayerType }],
      },
      select: { id: true },
    });

    if (pool.length < PRAYER_QUIZ_QUESTION_COUNT) {
      throw new BusinessException('INSUFFICIENT_PRAYER_QUESTIONS', HttpStatus.SERVICE_UNAVAILABLE);
    }

    const pickedIds = this.pickRandom(
      pool.map((p) => p.id),
      PRAYER_QUIZ_QUESTION_COUNT,
    );
    const expiresAt = slot.windowEndsAt
      .plus({ minutes: PRAYER_QUIZ_EXPIRY_GRACE_MINUTES })
      .toJSDate();

    const submission = await this.prisma.prayerQuizSubmission.create({
      data: {
        userId,
        prayerType,
        prayerDate: prayerDate.toUtcMidnight(),
        timezone,
        questionIds: pickedIds,
        windowStartsAt: slot.windowStartsAt.toJSDate(),
        windowEndsAt: slot.windowEndsAt.toJSDate(),
        expiresAt,
        status: 'PENDING',
        attemptCount: 0,
      },
    });

    const questions = await this.loadQuestionsForSubmission(pickedIds);

    return {
      quizId: submission.id,
      expiresAt: submission.expiresAt.toISOString(),
      questions,
    };
  }

  async validateAnswers(
    tx: Prisma.TransactionClient,
    args: {
      userId: string;
      quizId: string;
      answers: QuizAnswerDto[];
      now: DateTime;
    },
  ): Promise<{
    submission: NonNullable<Awaited<ReturnType<typeof tx.prayerQuizSubmission.findUnique>>>;
  }> {
    const { userId, quizId, answers, now } = args;

    const submission = await tx.prayerQuizSubmission.findUnique({
      where: { id: quizId },
    });
    if (!submission || submission.userId !== userId) {
      throw new BusinessException('QUIZ_NOT_FOUND', HttpStatus.NOT_FOUND);
    }
    if (submission.status !== 'PENDING') {
      throw new BusinessException('QUIZ_NOT_PENDING', HttpStatus.CONFLICT);
    }
    if (submission.expiresAt <= now.toJSDate()) {
      await tx.prayerQuizSubmission.update({
        where: { id: quizId },
        data: { status: 'EXPIRED' },
      });
      throw new BusinessException('QUIZ_EXPIRED', HttpStatus.GONE);
    }
    if (now.toJSDate() < submission.windowStartsAt || now.toJSDate() > submission.windowEndsAt) {
      throw new BusinessException('PRAYER_WINDOW_CLOSED', HttpStatus.CONFLICT);
    }
    if (answers.length !== submission.questionIds.length) {
      throw new BusinessException('ANSWER_COUNT_MISMATCH', HttpStatus.BAD_REQUEST);
    }
    const submittedIds = new Set(answers.map((a) => a.questionId));
    for (const qid of submission.questionIds) {
      if (!submittedIds.has(qid)) {
        throw new BusinessException('ANSWER_QUESTION_MISMATCH', HttpStatus.BAD_REQUEST);
      }
    }

    const options = await tx.prayerQuestionOption.findMany({
      where: { questionId: { in: submission.questionIds } },
    });
    const optionById = new Map(options.map((o) => [o.id, o]));

    let allCorrect = true;
    for (const answer of answers) {
      const opt = optionById.get(answer.optionId);
      if (!opt || opt.questionId !== answer.questionId || !opt.isCorrect) {
        allCorrect = false;
        break;
      }
    }

    await tx.prayerQuizSubmission.update({
      where: { id: quizId },
      data: {
        attemptCount: { increment: 1 },
        submittedAt: now.toJSDate(),
        status: allCorrect ? 'PENDING' : 'FAILED',
      },
    });

    if (!allCorrect) {
      throw new BusinessException('QUIZ_ANSWERS_INCORRECT', HttpStatus.UNPROCESSABLE_ENTITY);
    }

    return { submission };
  }

  async markPassed(
    tx: Prisma.TransactionClient,
    quizId: string,
    prayerCompletionId: string,
  ): Promise<void> {
    await tx.prayerQuizSubmission.update({
      where: { id: quizId },
      data: {
        status: 'PASSED',
        prayerCompletionId,
      },
    });
  }

  private assertWindowOpen(slot: PrayerSlot, now: DateTime): void {
    if (!isWithinWindow(slot, now)) {
      if (now < slot.windowStartsAt) {
        throw new BusinessException('PRAYER_WINDOW_NOT_OPEN_YET', HttpStatus.CONFLICT);
      }
      throw new BusinessException('PRAYER_WINDOW_CLOSED', HttpStatus.CONFLICT);
    }
  }

  private async assertNotAlreadyCompleted(
    userId: string,
    slot: PrayerSlot,
    zonedDate: DateTime,
    timezone: string,
  ): Promise<void> {
    const prayerDate = LocalDate.fromInstant(zonedDate, timezone);
    const existing = await this.prisma.prayerCompletion.findUnique({
      where: {
        userId_prayerType_prayerDate: {
          userId,
          prayerType: slot.type,
          prayerDate: prayerDate.toUtcMidnight(),
        },
      },
      select: { id: true },
    });
    if (existing) {
      throw new BusinessException('PRAYER_ALREADY_COMPLETED', HttpStatus.CONFLICT);
    }
  }

  private pickRandom<T>(pool: T[], count: number): T[] {
    if (count > pool.length) {
      throw new Error('pickRandom: count exceeds pool size');
    }
    const arr = [...pool];
    for (let i = 0; i < count; i++) {
      const j = i + Math.floor(Math.random() * (arr.length - i));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.slice(0, count);
  }

  private async loadQuestionsForSubmission(ids: string[]): Promise<QuestionPublicDto[]> {
    const questions: (PrayerQuestion & {
      options: { id: string; text: string; orderIndex: number }[];
    })[] = await this.prisma.prayerQuestion.findMany({
      where: { id: { in: ids } },
      include: {
        options: {
          select: { id: true, text: true, orderIndex: true },
          orderBy: { orderIndex: 'asc' },
        },
      },
    });

    const byId = new Map(questions.map((q) => [q.id, q]));
    return ids
      .map((id) => byId.get(id))
      .filter((q): q is NonNullable<typeof q> => Boolean(q))
      .map((q) => ({
        id: q.id,
        prompt: q.prompt,
        options: q.options.map((o) => ({ id: o.id, text: o.text })),
      }));
  }
}
