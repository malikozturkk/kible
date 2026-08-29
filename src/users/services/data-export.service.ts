import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class DataExportService {
  constructor(private readonly prisma: PrismaService) {}

  async exportUserData(userId: string): Promise<Record<string, unknown>> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        username: true,
        createdAt: true,
        updatedAt: true,
        country: true,
        city: true,
        latitude: true,
        longitude: true,
        madhab: true,
        language: true,
        locationChangeCount: true,
        madhabChangeCount: true,
        usernameUpdatedAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    const [
      consents,
      avatarConfig,
      xp,
      streak,
      prayerStats,
      prayerCompletions,
      quizSubmissions,
      questionMastery,
      fastingDays,
      streakFreezeUsages,
      following,
      followers,
      notificationPreferences,
      pushSubscriptions,
      credentialMeta,
    ] = await Promise.all([
      this.prisma.userConsent.findMany({
        where: { userId },
        select: { type: true, version: true, acceptedAt: true },
        orderBy: { acceptedAt: 'asc' },
      }),
      this.prisma.userAvatarConfig.findUnique({
        where: { userId },
        select: { colors: true, accessories: true, gender: true, updatedAt: true },
      }),
      this.prisma.userXp.findUnique({
        where: { userId },
        select: { xp: true, totalXp: true, updatedAt: true },
      }),
      this.prisma.userStreak.findUnique({
        where: { userId },
        select: {
          currentStreak: true,
          longestStreak: true,
          streakFreezeCount: true,
          lastActiveDate: true,
          recoverableStreak: true,
          brokenSinceDate: true,
        },
      }),
      this.prisma.userPrayerStats.findUnique({ where: { userId } }),
      this.prisma.prayerCompletion.findMany({
        where: { userId },
        select: {
          prayerType: true,
          prayerDate: true,
          completedAt: true,
          timezone: true,
          status: true,
          xpAwarded: true,
          isFirstOfDay: true,
          streakContributed: true,
        },
        orderBy: { prayerDate: 'asc' },
      }),
      this.prisma.prayerQuizSubmission.findMany({
        where: { userId },
        select: {
          prayerType: true,
          prayerDate: true,
          status: true,
          attemptCount: true,
          submittedAt: true,
          createdAt: true,
        },
        orderBy: { prayerDate: 'asc' },
      }),
      this.prisma.questionMastery.findMany({
        where: { userId },
        select: {
          questionId: true,
          correctStreak: true,
          totalCorrect: true,
          totalWrong: true,
          lastAnsweredAt: true,
          dueAt: true,
        },
      }),
      this.prisma.fastingDay.findMany({
        where: { userId },
        select: { fastDate: true, status: true, xpAwarded: true, hijriYear: true },
        orderBy: { fastDate: 'asc' },
      }),
      this.prisma.streakFreezeUsage.findMany({
        where: { userId },
        select: { protectedDate: true, usedAt: true, reason: true },
      }),
      this.prisma.follow.findMany({
        where: { followerId: userId },
        select: { createdAt: true, following: { select: { username: true } } },
      }),
      this.prisma.follow.findMany({
        where: { followingId: userId },
        select: { createdAt: true, follower: { select: { username: true } } },
      }),
      this.prisma.notificationPreference.findMany({
        where: { userId },
        select: { topic: true, enabled: true, optedInAt: true, optedOutAt: true },
      }),
      this.prisma.pushSubscription.findMany({
        where: { userId },
        select: { userAgent: true, createdAt: true, lastSeenAt: true },
      }),
      this.prisma.userCredential.findUnique({
        where: { userId },
        select: { passwordUpdatedAt: true, createdAt: true },
      }),
    ]);

    return {
      meta: {
        format: 'namazgo-kvkk-export',
        version: 1,
        generatedAt: new Date().toISOString(),
        note:
          'Bu belge KVKK m.11 kapsamında hesabınıza ait verilerin kopyasıdır. ' +
          'Parola, oturum anahtarları ve bildirim abonelik anahtarları güvenlik gereği ' +
          'dahil edilmemiştir.',
      },
      profile: user,
      account: credentialMeta,
      consents,
      avatarConfig,
      gamification: { xp, streak, prayerStats, streakFreezeUsages },
      prayers: prayerCompletions,
      quizzes: { submissions: quizSubmissions, mastery: questionMastery },
      fasting: fastingDays,
      social: {
        following: following.map((f) => ({
          username: f.following.username,
          since: f.createdAt,
        })),
        followers: followers.map((f) => ({
          username: f.follower.username,
          since: f.createdAt,
        })),
      },
      notifications: { preferences: notificationPreferences, devices: pushSubscriptions },
    };
  }
}
