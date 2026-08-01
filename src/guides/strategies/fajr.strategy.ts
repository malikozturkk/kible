import { Injectable } from '@nestjs/common';
import { GuideStrategy } from './guide.strategy';
import { GuideType } from '../enums/guide-type.enum';
import { GuideResponseDto } from '../dto/guide-response.dto';
import { PrayerStepBuilder } from './prayer-step.builder';
import { StepDto } from '../dto/step.dto';

@Injectable()
export class FajrStrategy extends GuideStrategy {
  supports(type: GuideType): boolean {
    return type === GuideType.FAJR;
  }

  async getGuide(): Promise<GuideResponseDto> {
    const steps: StepDto[] = [];
    let idx = 1;
    const totalRakats = 2;
    steps.push({
      ...PrayerStepBuilder.buildTakbirStep(idx++, 8),
      name: 'Niyet ve Tekbir',
    });

    steps.push(PrayerStepBuilder.buildQiyamWithRecitation(idx++, 8, 1, undefined, true));
    steps.push(PrayerStepBuilder.buildRukuh(idx++, 8, 1));
    steps.push(PrayerStepBuilder.buildIftiraj(idx++, 8, 1));
    steps.push(PrayerStepBuilder.buildSujud(idx++, 8, 1));
    steps.push(PrayerStepBuilder.buildQiyamWithRecitation(idx++, 8, 2, undefined, true));
    steps.push(PrayerStepBuilder.buildRukuh(idx++, 8, 2));
    steps.push(PrayerStepBuilder.buildIftiraj(idx++, 8, 2));
    steps.push(PrayerStepBuilder.buildSujud(idx++, 8, 2));
    steps.push(PrayerStepBuilder.buildTashahhudAndSalam(idx++, 8));

    PrayerStepBuilder.syncTotalSteps(steps);

    return {
      id: GuideType.FAJR,
      title: 'Sabah Namazı',
      totalSteps: steps.length,
      totalRakats,
      sunnahBefore: 2,
      steps,
    };
  }
}
