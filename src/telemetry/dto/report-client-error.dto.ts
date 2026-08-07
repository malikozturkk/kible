import { IsIn, IsOptional, IsString, MaxLength } from 'class-validator';

export const CLIENT_ERROR_SOURCES = [
  'window_error',
  'unhandled_rejection',
  'react_render_error',
] as const;

export type ClientErrorSource = (typeof CLIENT_ERROR_SOURCES)[number];

export class ReportClientErrorDto {
  @IsString()
  @MaxLength(500)
  message: string;

  @IsIn(CLIENT_ERROR_SOURCES)
  source: ClientErrorSource;

  @IsOptional()
  @IsString()
  @MaxLength(8000)
  stack?: string;

  @IsOptional()
  @IsString()
  @MaxLength(300)
  url?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  digest?: string;
}
