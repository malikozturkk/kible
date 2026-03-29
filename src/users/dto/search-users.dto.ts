import { IsString, IsNotEmpty, IsInt, Min, Max, IsOptional } from 'class-validator';
import { Type } from 'class-transformer';

export class SearchUsersDto {
  @IsString()
  @IsNotEmpty()
  query: string;

  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(50)
  pageSize: number;

  @Type(() => Number)
  @IsInt()
  @Min(0)
  @IsOptional()
  cursor: number = 0;
}
