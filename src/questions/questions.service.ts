import { Injectable, NotFoundException } from '@nestjs/common';
import { Question } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { RandomQuestionPublicDto } from './dto/random-question.dto';
import { GuideCheckQuestionResponseDto } from './dto/guide-check-question.dto';

const RANDOM_QUESTION_SHOW_PROBABILITY = 0.8;

@Injectable()
export class QuestionsService {
  constructor(private readonly prisma: PrismaService) {}

  async pickRandomForGuide(guideId: string): Promise<Question | null> {
    const rows = await this.prisma.question.findMany({
      where: { guideId },
    });
    if (rows.length === 0) {
      return null;
    }
    const index = Math.floor(Math.random() * rows.length);
    return rows[index] ?? null;
  }

  async tryPickRandomQuestion(guideId: string): Promise<RandomQuestionPublicDto | null> {
    if (Math.random() > RANDOM_QUESTION_SHOW_PROBABILITY) {
      return null;
    }
    const dbQuestion = await this.pickRandomForGuide(guideId);
    if (!dbQuestion) {
      return null;
    }
    return {
      id: dbQuestion.id,
      question: dbQuestion.question,
      options: dbQuestion.options,
    };
  }

  async guideCheckAnswer(
    questionId: string,
    answer: string,
  ): Promise<GuideCheckQuestionResponseDto> {
    const row = await this.prisma.question.findUnique({
      where: { id: questionId },
      select: { correctAnswer: true },
    });
    if (!row) {
      throw new NotFoundException('QUESTION_NOT_FOUND');
    }
    const normalized = (s: string) => s.trim().toLocaleLowerCase('tr-TR');
    const isCorrect = normalized(answer) === normalized(row.correctAnswer);
    return { isCorrect, correctAnswer: row.correctAnswer };
  }
}
