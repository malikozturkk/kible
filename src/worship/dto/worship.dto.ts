import { IsString } from 'class-validator';
import { IsCalendarDate } from '../../common/validators/is-calendar-date.validator';

export class AdhanQueryDto {
  @IsString()
  @IsCalendarDate()
  date: string;
}
