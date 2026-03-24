import { StepDto } from '../dto/step.dto';

export class PrayerStepBuilder {
  static fatiha =
    'Bismillahirrahmanirrahim, Elhamdulillahi rabbil alemin, Errahmanirrahim, Maliki yevmiddin, Iyya ke na’budu ve iyya ke nesta’in, Ihdinas siratal mustakim, Siratallezine en’amte aleyhim, ğayril mağdubi aleyhim ve leddallin';

  static ikhlas =
    'Kul huvallahu ehad, Allahus samed, Lem yelid ve lem yuled, ve lem yekun lehü kufuven ehad';

  static buildTakbirStep(index: number, totalSteps: number): StepDto {
    return {
      step: index,
      totalSteps,
      type: 'takbir',
      name: 'Tekbir (Allahu Ekber)',
      shortDescription: 'Namaza Allahu Ekber diyerek başlayın',
      description: 'Ayakta Allahu Ekber diyerek namaza başlayın (niyet kalpten yapılır).',
      tips: ['Niyet kalptendir; dil ile tekbir sünnettir'],
    } as StepDto;
  }

  static buildQiyamWithRecitation(
    index: number,
    totalSteps: number,
    rekat: number,
    recitation?: string,
    isFard = true,
  ): StepDto {
    return {
      step: index,
      totalSteps,
      type: 'standing',
      name: `Kıyam ve Kıraat (Rekat ${rekat})`,
      shortDescription: 'Fatiha ve kısa sure okuyun',
      description: 'Fatiha okuduktan sonra kısa bir sure (örnek: İhlas) okuyun.',
      recitation: `${this.fatiha}${recitation ? ' ' + recitation : ' ' + this.ikhlas}`,
      isFard,
      rekat,
      tips: ['Sükun içinde okunmalı', 'Anlamına dikkat edilmeye çalışılmalı'],
    } as StepDto;
  }

  static buildRukuh(index: number, totalSteps: number, rekat: number): StepDto {
    return {
      step: index,
      totalSteps,
      type: 'ruku',
      name: `Rükû (Rekat ${rekat})`,
      shortDescription: 'Eller dizlere gelecek şekilde eğilin',
      description:
        'Sırt düz, eller dizlere gelecek şekilde eğilin ve üç kere Subhana Rabbiyal Azeem deyin.',
      rekat,
      tips: ['Sırtın düz olması önemli', 'Hareket sakin olmalı'],
    } as StepDto;
  }

  static buildIftiraj(index: number, totalSteps: number, rekat: number): StepDto {
    return {
      step: index,
      totalSteps,
      type: 'after_standing',
      name: `Kıyam sonrası (Rekat ${rekat})`,
      shortDescription: 'Rükûdan kalkıp kısa bir duruş',
      description: 'Rükudan kalkıp ayağa kalkın, kısa süre durun.',
      rekat,
    } as StepDto;
  }

  static buildSujud(index: number, totalSteps: number, rekat: number): StepDto {
    return {
      step: index,
      totalSteps,
      type: 'prostration',
      name: `Secde (Rekat ${rekat})`,
      shortDescription: 'İki secde yapın',
      description: 'İki secde yapın; her birinde Subhana Rabbiyal A’la deyin.',
      rekat,
      tips: ['Alın ve burun yere temas etmeli', 'Secdede dil ile zikir yapılabilir'],
    } as StepDto;
  }

  static buildTashahhudAndSalam(index: number, totalSteps: number): StepDto {
    return {
      step: index,
      totalSteps,
      type: 'salutation',
      name: 'Et-Tahiyyat ve Selam',
      shortDescription: 'Et-Tahiyyat okuyun ve selam verin',
      description: 'Oturduktan sonra Et-Tahiyyat okuyun ve namazı selam ile bitirin.',
      tips: ['Selam sağa ve sola verilir'],
    } as StepDto;
  }
}
