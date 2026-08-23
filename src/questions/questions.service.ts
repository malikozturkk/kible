import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { QuestionScope } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { RandomQuestionPublicDto } from './dto/random-question.dto';
import { GuideCheckQuestionResponseDto } from './dto/guide-check-question.dto';

const RANDOM_QUESTION_SHOW_PROBABILITY = 0.8;

@Injectable()
export class QuestionsService {
  constructor(private readonly prisma: PrismaService) {}

  async tryPickRandomQuestion(guideId: string): Promise<RandomQuestionPublicDto | null> {
    if (Math.random() > RANDOM_QUESTION_SHOW_PROBABILITY) {
      return null;
    }

    const rows = await this.prisma.prayerQuestion.findMany({
      where: { scope: QuestionScope.GUIDE, guideId, isActive: true },
      select: {
        id: true,
        prompt: true,
        options: {
          select: { id: true, text: true },
          orderBy: { orderIndex: 'asc' },
        },
      },
    });

    const picked = rows[Math.floor(Math.random() * rows.length)];
    if (!picked) {
      return null;
    }

    return {
      id: picked.id,
      question: picked.prompt,
      options: picked.options.map((o) => ({ id: o.id, text: o.text })),
    };
  }

  async guideCheckAnswer(
    questionId: string,
    optionId: string,
  ): Promise<GuideCheckQuestionResponseDto> {
    const question = await this.prisma.prayerQuestion.findFirst({
      where: { id: questionId, scope: QuestionScope.GUIDE },
      select: { explanation: true, options: { select: { id: true, isCorrect: true } } },
    });
    if (!question) {
      throw new NotFoundException('QUESTION_NOT_FOUND');
    }

    const selected = question.options.find((o) => o.id === optionId);
    if (!selected) {
      throw new BadRequestException('QUIZ_OPTION_INVALID');
    }

    const correct = question.options.find((o) => o.isCorrect);
    if (!correct) {
      throw new NotFoundException('QUESTION_HAS_NO_CORRECT_OPTION');
    }

    return {
      isCorrect: selected.isCorrect,
      correctOptionId: correct.id,
      explanation: question.explanation,
    };
  }
}
