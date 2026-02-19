import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';

@Injectable()
export class FastingProgressService {
    calculate(fajr: DateTime, maghrib: DateTime, now: DateTime): number | null {
        if (now <= fajr || now >= maghrib) {
            return null;
        }
        const totalDuration = maghrib.diff(fajr).as('milliseconds');
        const passedDuration = now.diff(fajr).as('milliseconds');
        return parseFloat(((passedDuration / totalDuration) * 100).toFixed(2));
    }
}
