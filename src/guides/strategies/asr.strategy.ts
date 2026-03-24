import { Injectable } from '@nestjs/common';
import { GuideStrategy } from './guide.strategy';
import { GuideType } from '../enums/guide-type.enum';
import { GuideResponseDto } from '../dto/guide-response.dto';
import { PrayerStepBuilder } from './prayer-step.builder';
import { StepDto } from '../dto/step.dto';

@Injectable()
export class AsrStrategy extends GuideStrategy {
  supports(type: GuideType): boolean {
    return type === GuideType.ASR;
  }

  async getGuide(): Promise<GuideResponseDto> {
    const steps: StepDto[] = [];
    let idx = 1;
    const totalRakats = 4;

    steps.push({
      ...PrayerStepBuilder.buildTakbirStep(idx++, 16),
      name: 'Niyet ve Tekbir',
    });

    for (let r = 1; r <= totalRakats; r++) {
      steps.push(PrayerStepBuilder.buildQiyamWithRecitation(idx++, 16, r));
      steps.push(PrayerStepBuilder.buildRukuh(idx++, 16, r));
      steps.push(PrayerStepBuilder.buildIftiraj(idx++, 16, r));
      steps.push(PrayerStepBuilder.buildSujud(idx++, 16, r));
      if (r === totalRakats) {
        steps.push(PrayerStepBuilder.buildTashahhudAndSalam(idx++, 16));
      }
    }

    PrayerStepBuilder.syncTotalSteps(steps);

    return {
      id: GuideType.ASR,
      title: 'İkindi Namazı',
      totalSteps: steps.length,
      totalRakats,
      sunnahBefore: 0,
      sunnahAfter: 0,
      steps,
    } as GuideResponseDto;
  }
}
