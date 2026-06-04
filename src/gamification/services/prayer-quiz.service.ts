import { HttpStatus, Injectable } from '@nestjs/common';
import {
  Prisma,
  PrayerQuestion,
  PrayerQuizQuestion,
  PrayerQuizQuestionStatus,
  PrayerQuizStatus,
  PrayerType,
} from '@prisma/client';
import { DateTime } from 'luxon';
import { PrismaService } from '../../prisma/prisma.service';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LocalDate } from '../../common/utils/local-date';
import { PrayerSlot, PrayerScheduleParams } from '../types/gamification.types';
import {
  PRAYER_QUIZ_EXPIRY_GRACE_MINUTES,
  PRAYER_QUIZ_QUESTION_COUNT,
  PRAYER_QUIZ_QUESTION_TIME_LIMIT_GRACE_SECONDS,
  PRAYER_QUIZ_QUESTION_TIME_LIMIT_SECONDS,
} from '../constants/prayer.constants';
import { isWithinWindow } from '../helpers/prayer-schedule.helper';
import { PrayerScheduleService } from './prayer-schedule.service';
import {
  AnswerPrayerQuestionResponseDto,
  AnswerResultStatus,
  PrayerQuestionsResponseDto,
  QuestionOptionPublicDto,
  QuestionPublicDto,
  StartPrayerQuestionResponseDto,
} from '../dto/prayer-questions.dto';

const FINAL_QUESTION_STATUSES = new Set<PrayerQuizQuestionStatus>([
  PrayerQuizQuestionStatus.CORRECT,
  PrayerQuizQuestionStatus.INCORRECT,
  PrayerQuizQuestionStatus.EXPIRED,
  PrayerQuizQuestionStatus.LOCKED,
]);

type QuestionWithOptions = PrayerQuestion & {
  options: { id: string; text: string; orderIndex: number }[];
};

export interface AllCorrectResult {
  submissionId: string;
  prayerType: PrayerType;
}

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
    const prayerDateUtc = prayerDate.toUtcMidnight();

    await this.assertNotLockedOut(userId, prayerType, prayerDateUtc);

    const existing = await this.prisma.prayerQuizSubmission.findFirst({
      where: {
        userId,
        prayerType,
        prayerDate: prayerDateUtc,
        status: PrayerQuizStatus.PENDING,
        expiresAt: { gt: new Date() },
      },
      include: { questions: { orderBy: { orderIndex: 'asc' } } },
    });

    if (existing) {
      const refreshedQuestions = await this.expireOverdueQuestions(
        existing.id,
        existing.questions,
        now,
      );
      const failed = refreshedQuestions.find((q) => q.status === PrayerQuizQuestionStatus.EXPIRED);
      if (failed) {
        await this.failSubmission(existing.id, refreshedQuestions);
        throw new BusinessException('PRAYER_MARKING_LOCKED', HttpStatus.CONFLICT);
      }
      const questionMap = await this.loadQuestionsForSubmission(existing.questionIds);
      return this.buildIssueResponse(existing.id, existing.expiresAt, PrayerQuizStatus.PENDING, refreshedQuestions, questionMap);
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
        prayerDate: prayerDateUtc,
        timezone,
        questionIds: pickedIds,
        windowStartsAt: slot.windowStartsAt.toJSDate(),
        windowEndsAt: slot.windowEndsAt.toJSDate(),
        expiresAt,
        status: PrayerQuizStatus.PENDING,
        attemptCount: 0,
        questions: {
          create: pickedIds.map((qid, idx) => ({
            questionId: qid,
            orderIndex: idx,
            timeLimitSeconds: PRAYER_QUIZ_QUESTION_TIME_LIMIT_SECONDS,
            status: PrayerQuizQuestionStatus.PENDING,
          })),
        },
      },
      include: { questions: { orderBy: { orderIndex: 'asc' } } },
    });

    const questionMap = await this.loadQuestionsForSubmission(pickedIds);

    return this.buildIssueResponse(
      submission.id,
      submission.expiresAt,
      PrayerQuizStatus.PENDING,
      submission.questions,
      questionMap,
    );
  }

  async startQuestion(
    userId: string,
    quizId: string,
    questionId: string,
  ): Promise<StartPrayerQuestionResponseDto> {
    const submission = await this.prisma.prayerQuizSubmission.findUnique({
      where: { id: quizId },
      include: { questions: { orderBy: { orderIndex: 'asc' } } },
    });
    if (!submission || submission.userId !== userId) {
      throw new BusinessException('QUIZ_NOT_FOUND', HttpStatus.NOT_FOUND);
    }

    const now = DateTime.now().setZone(submission.timezone);
    await this.assertQuizUsable(submission, now);

    const refreshedQuestions = await this.expireOverdueQuestions(
      submission.id,
      submission.questions,
      now,
    );
    if (refreshedQuestions.some((q) => q.status === PrayerQuizQuestionStatus.EXPIRED)) {
      await this.failSubmission(submission.id, refreshedQuestions);
      throw new BusinessException('PRAYER_MARKING_LOCKED', HttpStatus.CONFLICT);
    }

    const target = refreshedQuestions.find((q) => q.questionId === questionId);
    if (!target) {
      throw new BusinessException('QUIZ_QUESTION_NOT_FOUND', HttpStatus.NOT_FOUND);
    }

    if (target.status !== PrayerQuizQuestionStatus.PENDING) {
      if (target.status === PrayerQuizQuestionStatus.SHOWN) {
        const questionMap = await this.loadQuestionsForSubmission(submission.questionIds);
        return {
          quizId: submission.id,
          quizStatus: submission.status,
          question: this.toPublicQuestion(target, questionMap.get(target.questionId)!, now),
        };
      }
      throw new BusinessException('QUIZ_QUESTION_NOT_STARTABLE', HttpStatus.CONFLICT);
    }

    const shownAt = now.toJSDate();
    const deadlineAt = now
      .plus({ seconds: PRAYER_QUIZ_QUESTION_TIME_LIMIT_SECONDS })
      .toJSDate();

    const updated = await this.prisma.prayerQuizQuestion.update({
      where: { id: target.id },
      data: {
        status: PrayerQuizQuestionStatus.SHOWN,
        shownAt,
        deadlineAt,
      },
    });

    const questionMap = await this.loadQuestionsForSubmission(submission.questionIds);

    return {
      quizId: submission.id,
      quizStatus: submission.status,
      question: this.toPublicQuestion(updated, questionMap.get(updated.questionId)!, now),
    };
  }

  async answerQuestion(
    userId: string,
    quizId: string,
    questionId: string,
    optionId: string,
  ): Promise<{
    response: AnswerPrayerQuestionResponseDto;
    allCorrect: AllCorrectResult | null;
  }> {
    return this.prisma.$transaction(async (tx) => {
      const submission = await tx.prayerQuizSubmission.findUnique({
        where: { id: quizId },
        include: { questions: { orderBy: { orderIndex: 'asc' } } },
      });
      if (!submission || submission.userId !== userId) {
        throw new BusinessException('QUIZ_NOT_FOUND', HttpStatus.NOT_FOUND);
      }

      const now = DateTime.now().setZone(submission.timezone);
      await this.assertQuizUsable(submission, now);

      const target = submission.questions.find((q) => q.questionId === questionId);
      if (!target) {
        throw new BusinessException('QUIZ_QUESTION_NOT_FOUND', HttpStatus.NOT_FOUND);
      }

      if (FINAL_QUESTION_STATUSES.has(target.status)) {
        throw new BusinessException('QUIZ_QUESTION_ALREADY_ANSWERED', HttpStatus.CONFLICT);
      }
      if (target.status === PrayerQuizQuestionStatus.PENDING) {
        throw new BusinessException('QUIZ_QUESTION_NOT_STARTED', HttpStatus.CONFLICT);
      }

      const deadlineAt = target.deadlineAt
        ? DateTime.fromJSDate(target.deadlineAt).setZone(submission.timezone)
        : null;
      const graceCutoff = deadlineAt?.plus({
        seconds: PRAYER_QUIZ_QUESTION_TIME_LIMIT_GRACE_SECONDS,
      });

      if (!deadlineAt || !graceCutoff || now > graceCutoff) {
        const expired = await tx.prayerQuizQuestion.update({
          where: { id: target.id },
          data: {
            status: PrayerQuizQuestionStatus.EXPIRED,
            answeredAt: now.toJSDate(),
          },
        });
        await this.lockRemainingQuestions(tx, submission.id, target.id);
        await tx.prayerQuizSubmission.update({
          where: { id: submission.id },
          data: {
            status: PrayerQuizStatus.FAILED,
            submittedAt: now.toJSDate(),
            attemptCount: { increment: 1 },
          },
        });
        const questionMap = await this.loadQuestionsForSubmission(submission.questionIds);
        const response: AnswerPrayerQuestionResponseDto = {
          quizId: submission.id,
          quizStatus: PrayerQuizStatus.FAILED,
          result: AnswerResultStatus.EXPIRED,
          isLocked: true,
          question: this.toPublicQuestion(expired, questionMap.get(expired.questionId)!, now),
        };
        return { response, allCorrect: null };
      }

      const option = await tx.prayerQuestionOption.findUnique({ where: { id: optionId } });
      if (!option || option.questionId !== target.questionId) {
        throw new BusinessException('QUIZ_OPTION_INVALID', HttpStatus.BAD_REQUEST);
      }

      const isCorrect = option.isCorrect;
      const nextStatus = isCorrect
        ? PrayerQuizQuestionStatus.CORRECT
        : PrayerQuizQuestionStatus.INCORRECT;

      const updated = await tx.prayerQuizQuestion.update({
        where: { id: target.id },
        data: {
          status: nextStatus,
          selectedOptionId: option.id,
          answeredAt: now.toJSDate(),
          isCorrect,
        },
      });

      const questionMap = await this.loadQuestionsForSubmission(submission.questionIds);

      if (!isCorrect) {
        await this.lockRemainingQuestions(tx, submission.id, target.id);
        await tx.prayerQuizSubmission.update({
          where: { id: submission.id },
          data: {
            status: PrayerQuizStatus.FAILED,
            submittedAt: now.toJSDate(),
            attemptCount: { increment: 1 },
          },
        });
        const response: AnswerPrayerQuestionResponseDto = {
          quizId: submission.id,
          quizStatus: PrayerQuizStatus.FAILED,
          result: AnswerResultStatus.INCORRECT,
          isLocked: true,
          question: this.toPublicQuestion(updated, questionMap.get(updated.questionId)!, now),
        };
        return { response, allCorrect: null };
      }

      const refreshed = await tx.prayerQuizQuestion.findMany({
        where: { submissionId: submission.id },
        orderBy: { orderIndex: 'asc' },
      });
      const allCorrectNow = refreshed.every(
        (q) => q.status === PrayerQuizQuestionStatus.CORRECT,
      );

      const response: AnswerPrayerQuestionResponseDto = {
        quizId: submission.id,
        quizStatus: submission.status,
        result: AnswerResultStatus.CORRECT,
        isLocked: false,
        question: this.toPublicQuestion(updated, questionMap.get(updated.questionId)!, now),
      };

      return {
        response,
        allCorrect: allCorrectNow
          ? { submissionId: submission.id, prayerType: submission.prayerType }
          : null,
      };
    });
  }

  async markPassed(
    tx: Prisma.TransactionClient,
    quizId: string,
    prayerCompletionId: string,
  ): Promise<void> {
    await tx.prayerQuizSubmission.update({
      where: { id: quizId },
      data: {
        status: PrayerQuizStatus.PASSED,
        prayerCompletionId,
      },
    });
  }

  private async assertQuizUsable(
    submission: { status: PrayerQuizStatus; expiresAt: Date; windowStartsAt: Date; windowEndsAt: Date },
    now: DateTime,
  ): Promise<void> {
    if (submission.status !== PrayerQuizStatus.PENDING) {
      throw new BusinessException('PRAYER_MARKING_LOCKED', HttpStatus.CONFLICT);
    }
    if (submission.expiresAt <= now.toJSDate()) {
      throw new BusinessException('QUIZ_EXPIRED', HttpStatus.GONE);
    }
    if (
      now.toJSDate() < submission.windowStartsAt ||
      now.toJSDate() >= submission.windowEndsAt
    ) {
      throw new BusinessException('PRAYER_WINDOW_CLOSED', HttpStatus.CONFLICT);
    }
  }

  private async expireOverdueQuestions(
    submissionId: string,
    questions: PrayerQuizQuestion[],
    now: DateTime,
  ): Promise<PrayerQuizQuestion[]> {
    const updates: PrayerQuizQuestion[] = [];
    for (const q of questions) {
      if (
        q.status === PrayerQuizQuestionStatus.SHOWN &&
        q.deadlineAt &&
        now.toJSDate() >
          new Date(
            q.deadlineAt.getTime() + PRAYER_QUIZ_QUESTION_TIME_LIMIT_GRACE_SECONDS * 1000,
          )
      ) {
        const updated = await this.prisma.prayerQuizQuestion.update({
          where: { id: q.id },
          data: {
            status: PrayerQuizQuestionStatus.EXPIRED,
            answeredAt: now.toJSDate(),
          },
        });
        updates.push(updated);
      } else {
        updates.push(q);
      }
    }
    return updates;
  }

  private async failSubmission(
    submissionId: string,
    questions: PrayerQuizQuestion[],
  ): Promise<void> {
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await this.lockRemainingQuestions(tx, submissionId, null);
      await tx.prayerQuizSubmission.update({
        where: { id: submissionId },
        data: {
          status: PrayerQuizStatus.FAILED,
          submittedAt: now,
        },
      });
    });
  }

  private async lockRemainingQuestions(
    tx: Prisma.TransactionClient,
    submissionId: string,
    excludeQuestionRowId: string | null,
  ): Promise<void> {
    await tx.prayerQuizQuestion.updateMany({
      where: {
        submissionId,
        status: { in: [PrayerQuizQuestionStatus.PENDING, PrayerQuizQuestionStatus.SHOWN] },
        ...(excludeQuestionRowId ? { id: { not: excludeQuestionRowId } } : {}),
      },
      data: {
        status: PrayerQuizQuestionStatus.LOCKED,
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

  private async assertNotLockedOut(
    userId: string,
    prayerType: PrayerType,
    prayerDateUtc: Date,
  ): Promise<void> {
    const failed = await this.prisma.prayerQuizSubmission.findFirst({
      where: {
        userId,
        prayerType,
        prayerDate: prayerDateUtc,
        status: { in: [PrayerQuizStatus.FAILED, PrayerQuizStatus.EXPIRED] },
      },
      select: { id: true },
    });
    if (failed) {
      throw new BusinessException('PRAYER_MARKING_LOCKED', HttpStatus.CONFLICT);
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

  private async loadQuestionsForSubmission(
    ids: string[],
  ): Promise<Map<string, QuestionWithOptions>> {
    const questions = await this.prisma.prayerQuestion.findMany({
      where: { id: { in: ids } },
      include: {
        options: {
          select: { id: true, text: true, orderIndex: true },
          orderBy: { orderIndex: 'asc' },
        },
      },
    });
    return new Map(questions.map((q) => [q.id, q]));
  }

  private buildIssueResponse(
    quizId: string,
    expiresAt: Date,
    quizStatus: PrayerQuizStatus,
    rows: PrayerQuizQuestion[],
    questionMap: Map<string, QuestionWithOptions>,
  ): PrayerQuestionsResponseDto {
    const now = DateTime.now();
    const isLocked = quizStatus !== PrayerQuizStatus.PENDING;
    return {
      quizId,
      expiresAt: expiresAt.toISOString(),
      quizStatus,
      isLocked,
      questions: rows
        .map((row) => {
          const meta = questionMap.get(row.questionId);
          if (!meta) return null;
          return this.toPublicQuestion(row, meta, now);
        })
        .filter((q): q is QuestionPublicDto => Boolean(q)),
    };
  }

  private toPublicQuestion(
    row: PrayerQuizQuestion,
    meta: QuestionWithOptions,
    now: DateTime,
  ): QuestionPublicDto {
    const options: QuestionOptionPublicDto[] = meta.options.map((o) => ({
      id: o.id,
      text: o.text,
    }));
    const deadlineAtIso = row.deadlineAt ? row.deadlineAt.toISOString() : null;
    const shownAtIso = row.shownAt ? row.shownAt.toISOString() : null;
    const answeredAtIso = row.answeredAt ? row.answeredAt.toISOString() : null;
    const isExpiredByClock = Boolean(
      row.deadlineAt &&
        now.toJSDate() >
          new Date(row.deadlineAt.getTime() + PRAYER_QUIZ_QUESTION_TIME_LIMIT_GRACE_SECONDS * 1000),
    );
    const isExpired =
      row.status === PrayerQuizQuestionStatus.EXPIRED ||
      (row.status === PrayerQuizQuestionStatus.SHOWN && isExpiredByClock);

    const isAnswerable =
      row.status === PrayerQuizQuestionStatus.SHOWN && !isExpired;
    const canBeAnsweredAgain = false;

    return {
      id: row.questionId,
      prompt: meta.prompt,
      options,
      orderIndex: row.orderIndex,
      timeLimitSeconds: row.timeLimitSeconds,
      status: row.status,
      shownAt: shownAtIso,
      deadlineAt: deadlineAtIso,
      answeredAt: answeredAtIso,
      selectedOptionId: row.selectedOptionId,
      isCorrect: row.isCorrect,
      isAnswerable,
      canBeAnsweredAgain,
      isExpired,
    };
  }
}
