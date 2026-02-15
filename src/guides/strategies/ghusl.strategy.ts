import { Injectable } from '@nestjs/common';
import { GuideStrategy } from './guide.strategy';
import { GuideType } from '../enums/guide-type.enum';
import { GuideResponseDto } from '../dto/guide-response.dto';

@Injectable()
export class GhuslStrategy extends GuideStrategy {
  supports(type: GuideType): boolean {
    return type === GuideType.GHUSL;
  }

  async getGuide(): Promise<GuideResponseDto> {
    const steps = [
      {
        step: 1,
        totalSteps: 6,
        name: 'Niyet etmek',
        bodyPart: 'Kalpten',
        repeat: '1 kez',
        shortDescription: 'Gusül yapmaya niyet edin',
        description: 'Gusül eylemine kalben niyet edilir; dil ile ifade edilmesi sünnettir.',
        tips: ['Niyet kalptendir', 'Kullandığınız su temiz olmalı'],
      },
      {
        step: 2,
        totalSteps: 6,
        name: 'Özel yerleri yıkamak',
        bodyPart: 'Cinsel organlar',
        repeat: 'Gerektiği kadar',
        shortDescription: 'Cinsel organlar temizlenir',
        description: 'Vücudunuzdaki kir ve necaset varsa önce temizlenir.',
        tips: ['Tuvalet sonrası yapılmalı', 'Eğer gerekli ise sabun kullanılabilir'],
      },
      {
        step: 3,
        totalSteps: 6,
        name: 'Tam abdest yapmak',
        bodyPart: 'Tüm vücut için hazırlık',
        repeat: 'Sünnet olarak',
        shortDescription: 'Gusül öncesi veya sırasında abdest alınır',
        description:
          'Birçok mezhebe göre gusül öncesi tam abdest almak müstehaptır veya şarttır; bu adım abdestin yapılmasını içerir.',
        tips: ['Abdest adımlarına dikkat edin', 'Eller ve ayaklar iyi yıkanmalı'],
      },
      {
        step: 4,
        totalSteps: 6,
        name: 'Başın üç kere su ile ıslatılması',
        bodyPart: 'Baş',
        repeat: '3 kez',
        shortDescription: 'Kafa derisine su dökülür',
        description:
          'Başın her tarafına su değecek şekilde üç kere su dökülür, özellikle saçlı deri suyla temas etmelidir.',
        tips: ['Saç çok yoğunsa suyu parmaklarla deriye ulaştırın'],
      },
      {
        step: 5,
        totalSteps: 6,
        name: 'Tüm bedenin yıkanması',
        bodyPart: 'Tüm vücut',
        repeat: '1 kez',
        shortDescription: 'Vücudun her yeri su ile yıkanır',
        description:
          'Sağ taraf, sol taraf ve gövde olmak üzere vücudun tüm bölgeleri su ile yıkanır; hiçbir yere kuru deri kalmamalıdır.',
        tips: [
          'Derinin altındaki kıvrımlar dikkatle yıkanmalı',
          'Kulak arkası, boyun arkası unutulmamalı',
        ],
      },
      {
        step: 6,
        totalSteps: 6,
        name: 'Sıranın ve eksiksizliğin kontrolü',
        bodyPart: 'Tüm vücut',
        repeat: '1 kez',
        shortDescription: 'Gusülün eksiksiz olduğundan emin olun',
        description: 'Bütün vücudu kontrol edin; suyla temas etmeyen yer kaldıysa tekrarlayın.',
        tips: ['Gusül sırasında niyet korunmalı', 'Gerekirse adımları tekrar edin'],
      },
    ];

    return {
      id: GuideType.GHUSL,
      title: 'Gusül Abdesti',
      totalSteps: steps.length,
      steps,
    } as GuideResponseDto;
  }
}
