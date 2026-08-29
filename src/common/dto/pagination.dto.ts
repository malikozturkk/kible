import { Type } from 'class-transformer';
import { IsInt, IsOptional, Max, Min } from 'class-validator';

export const PAGINATION_DEFAULT_PAGE_SIZE = 20;
export const PAGINATION_MAX_PAGE_SIZE = 50;

export class PaginationDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(PAGINATION_MAX_PAGE_SIZE)
  pageSize?: number;
}
