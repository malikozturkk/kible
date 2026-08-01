import { Type } from 'class-transformer';
import { IsArray, IsBoolean, IsInt, IsString, Matches, ValidateNested } from 'class-validator';

export class PrayerHistoryQueryDto {
  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'from must be YYYY-MM-DD' })
  from: string;

  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'to must be YYYY-MM-DD' })
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
