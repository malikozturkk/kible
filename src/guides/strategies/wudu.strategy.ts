import { Injectable } from '@nestjs/common';
import { GuideStrategy } from './guide.strategy';
import { GuideType } from '../enums/guide-type.enum';
import { GuideResponseDto } from '../dto/guide-response.dto';

@Injectable()
export class WuduStrategy extends GuideStrategy {
  supports(type: GuideType): boolean {
    return type === GuideType.WUDU;
  }

  async getGuide(): Promise<GuideResponseDto> {
    const steps = [
      {
        step: 1,
        totalSteps: 9,
        type: 'intend',
        name: 'Niyet etmek',
        bodyPart: 'Kalpten',
        repeat: '1 kez',
        shortDescription: 'Abdest almaya niyet edin',
        description:
          'Kalpten abdest almaya niyet edilir. Dil ile söylemek sünnettir fakat niyet kalptendir.',
        tips: ['Niyet kalple yapılır', 'Dil ile söylemek sünnettir'],
      },
      {
        step: 2,
        totalSteps: 9,
        type: 'wash_hands',
        name: 'Ellerin yıkanması',
        bodyPart: 'Eller',
        repeat: '3 kez',
        shortDescription: 'Eller bileklere kadar yıkanır',
        description: 'Ellerinizi bileklere kadar üçer kez yıkayın, parmak aralarını unutmayın.',
        tips: ['Parmak araları iyi sabunlanmalı', 'Tırnak altı temizlenmeli'],
      },
      {
        step: 3,
        totalSteps: 9,
        type: 'wash_mouth',
        name: 'Ağızın çalkalanması',
        bodyPart: 'Ağız',
        repeat: '3 kez',
        shortDescription: 'Ağız su ile çalkalanır',
        description: 'Ağzı üç kere su ile çalkalayın, her seferinde suyu derinlemesine dolaştırın.',
        tips: ['Ağız içi temizlenmeli', 'Dişler ise gereken zamanda fırçalanmalı'],
      },
      {
        step: 4,
        totalSteps: 9,
        type: 'wash_nose',
        name: 'Burnun temizlenmesi',
        bodyPart: 'Burun',
        repeat: '3 kez',
        shortDescription: 'Buruna su çekilip dışarı atılır',
        description: 'Sağ elle su çekip sol elle sümkürerek üç kez burun temizlenir.',
        tips: ['Nazikçe yapılmalı', 'Sümkürürken kuvvet uygulanmamalı'],
      },
      {
        step: 5,
        totalSteps: 9,
        type: 'wash_face',
        name: 'Yüzün yıkanması',
        bodyPart: 'Yüz',
        repeat: '3 kez',
        shortDescription: 'Yüz komple yıkanır',
        description: 'Alından çeneye, sağdan sola yüzün tamamını üçer kez yıkayın.',
        tips: ['Yüzün her yeri su ile temas etmeli'],
      },
      {
        step: 6,
        totalSteps: 9,
        type: 'wash_arms',
        name: 'Kolların dirseklere kadar yıkanması',
        bodyPart: 'Kollar',
        repeat: '3 kez (her kol)',
        shortDescription: 'Önce sağ kol, sonra sol kol yıkanır',
        description:
          'Önce sağ kol ucu parmaklara sonra dirseklere kadar, sonra sol kol aynı şekilde üçer kez yıkanır.',
        tips: ['Dirsekler de su ile temas etmeli', 'Parmak uçları unutulmamalı'],
      },
      {
        step: 7,
        totalSteps: 9,
        type: 'anoint_head',
        name: 'Başın mesh edilmesi',
        bodyPart: 'Baş',
        repeat: '1 kez',
        shortDescription: 'Başın ıslatılmış elle mesh edilmesi',
        description:
          'Islak ellerle başın önünden başlayıp arkasına kadar bir defa meshedin; başın tamamı üzerinden geçmelidir.',
        tips: ['Saç çok yoğunsa avuç içine su sürülüp üzerinden geçirilebilir'],
      },
      {
        step: 8,
        totalSteps: 9,
        type: 'wash_ears',
        name: 'Kulakların meshi',
        bodyPart: 'Kulaklar',
        repeat: '1 kez',
        shortDescription: 'Kulak iç-dış meshi',
        description:
          'Başın meshinden sonra işaret parmağı ile kulak içleri, başparmak ile kulak arkaları bir defa silinir.',
        tips: ['Kulaklar ve çevresi suyla temas etmeli'],
      },
      {
        step: 9,
        totalSteps: 9,
        type: 'wash_feet',
        name: 'Ayakların yıkanması',
        bodyPart: 'Ayaklar',
        repeat: '3 kez (her ayak)',
        shortDescription: 'Ayak bilekleri dahil yıkanır',
        description:
          'Önce sağ ayak sonra sol ayak üçer kez topuklara kadar yıkanır; parmak araları kurcalanmalı.',
        tips: ['Topuklar da su ile temas etmeli', 'Parmak araları unutulmamalı'],
      },
    ];

    return {
      id: GuideType.WUDU,
      title: 'Abdest',
      totalSteps: steps.length,
      steps,
    };
  }
}
