import { IsString, IsNotEmpty, Validate } from 'class-validator';
import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_REGEX = /^[a-zA-Z0-9_]+$/;

@ValidatorConstraint({ name: 'isIdentifier', async: false })
export class IsIdentifierConstraint implements ValidatorConstraintInterface {
  validate(value: string): boolean {
    if (!value || typeof value !== 'string') return false;
    return EMAIL_REGEX.test(value) || USERNAME_REGEX.test(value);
  }

  defaultMessage(): string {
    return 'INVALID_IDENTIFIER_FORMAT';
  }
}

export class LoginDto {
  @IsNotEmpty()
  @IsString()
  @Validate(IsIdentifierConstraint)
  identifier: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
