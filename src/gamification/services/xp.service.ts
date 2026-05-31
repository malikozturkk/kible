import { HttpStatus, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LevelCalculator } from '../domain/level-calculator';
import { XpAwardResultDto } from '../dto/xp-award-result.dto';

@Injectable()
export class XpService {
  constructor(private readonly prisma: PrismaService) {}

  async award(
    tx: Prisma.TransactionClient,
    userId: string,
    amount: number,
  ): Promise<XpAwardResultDto> {
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new BusinessException('INVALID_XP_AMOUNT', HttpStatus.BAD_REQUEST);
    }

    const updated = await tx.userXp.upsert({
      where: { userId },
      update: {
        xp: { increment: amount },
        totalXp: { increment: amount },
      },
      create: {
        userId,
        xp: amount,
        totalXp: amount,
      },
    });

    const before = updated.xp - amount;
    const levelBefore = LevelCalculator.computeLevelFromXp(before).level;
    const after = LevelCalculator.computeLevelFromXp(updated.xp);
    const leveledUp = after.level > levelBefore;

    return {
      xpAwarded: amount,
      xp: updated.xp,
      totalXp: updated.totalXp,
      level: after.level,
      leveledUp,
      progressPercent: after.progressPercent,
    };
  }
}
