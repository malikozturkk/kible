import { Injectable } from '@nestjs/common';
import { GuideStrategy } from './guide.strategy';
import { GuideType } from '../enums/guide-type.enum';
import { GuideResponseDto } from '../dto/guide-response.dto';
import { PrayerStepBuilder } from './prayer-step.builder';
import { StepDto } from '../dto/step.dto';

@Injectable()
export class JumuahStrategy extends GuideStrategy {
  supports(type: GuideType): boolean {
    return type === GuideType.JUMUAH;
  }

  async getGuide(): Promise<GuideResponseDto> {
    const steps: StepDto[] = [];
    let idx = 1;
    const totalRakats = 2;

    steps.push({
      step: idx++,
      totalSteps: 6,
      type: 'khutbah',
      name: 'Hutbe (Khutbah) dinleme',
      shortDescription: 'Cemaatle hutbeyi oturarak dinleyin',
      description: 'Cuma namazından önce hutbeler verilir; dikkatlice dinleyin ve sessiz olun.',
      tips: ['Hutbe sünnettir, katılım tavsiye edilir'],
    });

    steps.push({
      ...PrayerStepBuilder.buildTakbirStep(idx++, 6),
      name: 'Niyet ve Tekbir',
    });

    for (let r = 1; r <= totalRakats; r++) {
      steps.push(PrayerStepBuilder.buildQiyamWithRecitation(idx++, 6, r));
      steps.push(PrayerStepBuilder.buildRukuh(idx++, 6, r));
      steps.push(PrayerStepBuilder.buildIftiraj(idx++, 6, r));
      steps.push(PrayerStepBuilder.buildSujud(idx++, 6, r));
      if (r === totalRakats) {
        steps.push(PrayerStepBuilder.buildTashahhudAndSalam(idx++, 6));
      }
    }

    PrayerStepBuilder.syncTotalSteps(steps);

    return {
      id: GuideType.JUMUAH,
      title: 'Cuma Namazı',
      totalSteps: steps.length,
      totalRakats,
      steps,
    } as GuideResponseDto;
  }
}
