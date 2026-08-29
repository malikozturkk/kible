import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { PasswordHashScheme } from '@prisma/client';
import { BCRYPT_COST } from '../constants/profile.constants';

function preHash(password: string, pepper: string): string {
  return crypto.createHmac('sha256', pepper).update(password, 'utf8').digest('base64');
}

export function hashPassword(password: string, pepper: string): Promise<string> {
  return bcrypt.hash(preHash(password, pepper), BCRYPT_COST);
}

export const CURRENT_HASH_SCHEME = PasswordHashScheme.HMAC_BCRYPT;

export function verifyPassword(
  password: string,
  storedHash: string,
  scheme: PasswordHashScheme,
  pepper: string,
): Promise<boolean> {
  if (scheme === PasswordHashScheme.LEGACY_CONCAT) {
    return bcrypt.compare(password + pepper, storedHash);
  }
  return bcrypt.compare(preHash(password, pepper), storedHash);
}
