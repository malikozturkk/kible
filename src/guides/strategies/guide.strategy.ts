import { GuideResponseDto } from '../dto/guide-response.dto';
import { GuideType } from '../enums/guide-type.enum';

export abstract class GuideStrategy {
  abstract supports(type: GuideType): boolean;
  abstract getGuide(): Promise<GuideResponseDto>;
}
