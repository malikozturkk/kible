import { IsString } from 'class-validator';

export class AdhanQueryDto {
  @IsString()
  date: string;

  @IsString()
  tz: string;
}
