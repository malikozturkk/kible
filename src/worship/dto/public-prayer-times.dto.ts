import { Type } from 'class-transformer';
import { IsInt, IsNotEmpty, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';
import { IsCalendarDate } from '../../common/validators/is-calendar-date.validator';

export const PUBLIC_PRAYER_TIMES_MAX_DAYS = 31;
export const PUBLIC_PRAYER_TIMES_DEFAULT_DAYS = 7;

export class PublicPrayerTimesQueryDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  city: string;

  @IsOptional()
  @IsString()
  @IsCalendarDate()
  date?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(PUBLIC_PRAYER_TIMES_MAX_DAYS)
  days?: number;
}
