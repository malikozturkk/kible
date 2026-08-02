import { Injectable } from '@nestjs/common';
import { PrayerQuizQuestionStatus, PrayerQuizStatus } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { PRAYER_QUIZ_QUESTION_TIME_LIMIT_GRACE_SECONDS } from '../constants/prayer.constants';

@Injectable()
export class PrayerQuizExpiryService {
  constructor(private readonly prisma: PrismaService) {}

  async sweepStaleSubmissions(userId: string, prayerDateUtc: Date, now: Date): Promise<void> {
    const pending = await this.prisma.prayerQuizSubmission.findMany({
      where: { userId, prayerDate: prayerDateUtc, status: PrayerQuizStatus.PENDING },
      select: {
        id: true,
        expiresAt: true,
        questions: { select: { id: true, status: true, deadlineAt: true } },
      },
    });

    if (pending.length === 0) return;

    const graceMs = PRAYER_QUIZ_QUESTION_TIME_LIMIT_GRACE_SECONDS * 1000;

    for (const submission of pending) {
      const overdueQuestionIds = submission.questions
        .filter(
          (q) =>
            q.status === PrayerQuizQuestionStatus.SHOWN &&
            q.deadlineAt !== null &&
            now.getTime() > q.deadlineAt.getTime() + graceMs,
        )
        .map((q) => q.id);

      const submissionOutlived = now.getTime() > submission.expiresAt.getTime();
      if (overdueQuestionIds.length === 0 && !submissionOutlived) continue;

      await this.prisma.$transaction(async (tx) => {
        if (overdueQuestionIds.length > 0) {
          await tx.prayerQuizQuestion.updateMany({
            where: { id: { in: overdueQuestionIds } },
            data: { status: PrayerQuizQuestionStatus.EXPIRED, answeredAt: now },
          });
        }

        await tx.prayerQuizQuestion.updateMany({
          where: {
            submissionId: submission.id,
            status: {
              in: [PrayerQuizQuestionStatus.PENDING, PrayerQuizQuestionStatus.SHOWN],
            },
          },
          data: { status: PrayerQuizQuestionStatus.LOCKED },
        });

        await tx.prayerQuizSubmission.update({
          where: { id: submission.id },
          data: {
            status: PrayerQuizStatus.FAILED,
            submittedAt: now,
            attemptCount: { increment: 1 },
          },
        });
      });
    }
  }
}
