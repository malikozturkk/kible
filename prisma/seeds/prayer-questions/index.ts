import { SeedPrayerQuestionGroup } from '../seed-types';
import { FAJR_QUESTIONS } from './fajr';
import { DHUHR_QUESTIONS } from './dhuhr';
import { ASR_QUESTIONS } from './asr';
import { MAGHRIB_QUESTIONS } from './maghrib';
import { ISHA_QUESTIONS } from './isha';
import { JUMUAH_QUESTIONS } from './jumuah';
import { TARAWIH_QUESTIONS } from './tarawih';
import { EID_FITR_QUESTIONS } from './eid-fitr';
import { EID_ADHA_QUESTIONS } from './eid-adha';
import { GENERAL_QUESTIONS } from './general';

export const PRAYER_QUESTION_GROUPS: SeedPrayerQuestionGroup[] = [
  { prayerType: 'FAJR', questions: FAJR_QUESTIONS },
  { prayerType: 'DHUHR', questions: DHUHR_QUESTIONS },
  { prayerType: 'ASR', questions: ASR_QUESTIONS },
  { prayerType: 'MAGHRIB', questions: MAGHRIB_QUESTIONS },
  { prayerType: 'ISHA', questions: ISHA_QUESTIONS },
  { prayerType: 'JUMUAH', questions: JUMUAH_QUESTIONS },
  { prayerType: 'TARAWIH', questions: TARAWIH_QUESTIONS },
  { prayerType: 'EID_FITR', questions: EID_FITR_QUESTIONS },
  { prayerType: 'EID_ADHA', questions: EID_ADHA_QUESTIONS },
  { prayerType: null, questions: GENERAL_QUESTIONS },
];
