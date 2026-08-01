import { Body, Controller, Post } from '@nestjs/common';
import { QuestionsService } from './questions.service';
import {
  GuideCheckQuestionBodyDto,
  GuideCheckQuestionResponseDto,
} from './dto/guide-check-question.dto';

@Controller('question')
export class QuestionsController {
  constructor(private readonly questionsService: QuestionsService) {}

  @Post('guide/check')
  async check(@Body() body: GuideCheckQuestionBodyDto): Promise<GuideCheckQuestionResponseDto> {
    return this.questionsService.guideCheckAnswer(body.questionId, body.optionId);
  }
}
