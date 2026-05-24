import { IsNumber, IsOptional, IsString, MaxLength } from 'class-validator';
import { Type } from 'class-transformer';

export class AdhanQueryDto {
  @Type(() => Number)
  @IsNumber({ maxDecimalPlaces: 8 })
  lat: number;

  @Type(() => Number)
  @IsNumber({ maxDecimalPlaces: 8 })
  lng: number;

  @IsString()
  date: string;

  @IsString()
  tz: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  method?: string;

  @IsOptional()
  @IsString()
  @MaxLength(32)
  madhab?: string;
}
