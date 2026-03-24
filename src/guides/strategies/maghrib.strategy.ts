import { Injectable } from '@nestjs/common';
import { GuideStrategy } from './guide.strategy';
import { GuideType } from '../enums/guide-type.enum';
import { GuideResponseDto } from '../dto/guide-response.dto';
import { PrayerStepBuilder } from './prayer-step.builder';
import { StepDto } from '../dto/step.dto';

@Injectable()
export class MaghribStrategy extends GuideStrategy {
  supports(type: GuideType): boolean {
    return type === GuideType.MAGHRIB;
  }

  async getGuide(): Promise<GuideResponseDto> {
    const steps: StepDto[] = [];
    let idx = 1;
    const totalRakats = 3;

    steps.push({
      ...PrayerStepBuilder.buildTakbirStep(idx++, 12),
      name: 'Niyet ve Tekbir',
    });

    for (let r = 1; r <= totalRakats; r++) {
      steps.push(PrayerStepBuilder.buildQiyamWithRecitation(idx++, 12, r));
      steps.push(PrayerStepBuilder.buildRukuh(idx++, 12, r));
      steps.push(PrayerStepBuilder.buildIftiraj(idx++, 12, r));
      steps.push(PrayerStepBuilder.buildSujud(idx++, 12, r));
      if (r === totalRakats) {
        steps.push(PrayerStepBuilder.buildTashahhudAndSalam(idx++, 12));
      }
    }

    PrayerStepBuilder.syncTotalSteps(steps);

    return {
      id: GuideType.MAGHRIB,
      title: 'Akşam Namazı',
      totalSteps: steps.length,
      totalRakats,
      sunnahAfter: 2,
      steps,
    } as GuideResponseDto;
  }
}
