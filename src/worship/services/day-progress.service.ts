import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';

@Injectable()
export class DayProgressService {
    calculate(now: DateTime): number {
        const secondsSinceMidnight = now.diff(now.startOf('day')).as('seconds');
        return parseFloat(((secondsSinceMidnight / 86400) * 100).toFixed(2));
    }
}
