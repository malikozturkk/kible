import { Type } from 'class-transformer';
import { IsArray, IsBoolean, IsInt, IsString, ValidateNested } from 'class-validator';
import { IsCalendarDate } from '../../common/validators/is-calendar-date.validator';

export class PrayerHistoryQueryDto {
  @IsString()
  @IsCalendarDate({ message: 'from must be YYYY-MM-DD' })
  from: string;

  @IsString()
  @IsCalendarDate({ message: 'to must be YYYY-MM-DD' })
  to: string;
}

export class PrayerHistoryDayDto {
  @IsString()
  date: string;

  @IsInt()
  completedCount: number;

  @IsInt()
  totalCount: number;

  @IsBoolean()
  isComplete: boolean;

  @IsBoolean()
  isFrozen: boolean;
}

export class PrayerHistoryResponseDto {
  @IsString()
  from: string;

  @IsString()
  to: string;

  @IsString()
  timezone: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PrayerHistoryDayDto)
  days: PrayerHistoryDayDto[];
}
