import { IsOptional, Matches } from 'class-validator';

const HEX_COLOR_6 = /^#[0-9A-Fa-f]{6}$/;
export class AvatarColorsDto {
  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  iris?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  pupil?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  hair?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  skin?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  lips?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  nose?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  earInner?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  neck?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  eyebrow?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  outfit?: string;

  @IsOptional()
  @Matches(HEX_COLOR_6, { message: 'INVALID_HEX_COLOR' })
  background?: string;
}
