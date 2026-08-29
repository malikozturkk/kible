import type { Request, Response } from 'express';

export const REFRESH_TOKEN_COOKIE = 'refresh_token';
const REFRESH_TOKEN_MAX_AGE_MS = 24 * 60 * 60 * 1000;
type SameSite = 'lax' | 'strict' | 'none';

function resolveSameSite(): SameSite {
  const configured = (process.env.COOKIE_SAMESITE ?? 'lax').toLowerCase();
  return configured === 'none' || configured === 'strict' ? configured : 'lax';
}

function isSecure(sameSite: SameSite): boolean {
  return sameSite === 'none' || process.env.NODE_ENV === 'production';
}

function baseOptions() {
  const sameSite = resolveSameSite();
  return {
    httpOnly: true,
    sameSite,
    secure: isSecure(sameSite),
    path: '/',
    ...(process.env.COOKIE_DOMAIN ? { domain: process.env.COOKIE_DOMAIN } : {}),
  };
}

export function setRefreshTokenCookie(res: Response, refreshToken: string): void {
  res.cookie(REFRESH_TOKEN_COOKIE, refreshToken, {
    ...baseOptions(),
    maxAge: REFRESH_TOKEN_MAX_AGE_MS,
  });
}

export function clearRefreshTokenCookie(res: Response): void {
  res.clearCookie(REFRESH_TOKEN_COOKIE, baseOptions());
}

export function readRefreshTokenCookie(req: Request): string | null {
  const header = req.headers.cookie;
  if (!header) return null;

  for (const part of header.split(';')) {
    const separatorIndex = part.indexOf('=');
    if (separatorIndex === -1) continue;
    const name = part.slice(0, separatorIndex).trim();
    if (name !== REFRESH_TOKEN_COOKIE) continue;
    return decodeURIComponent(part.slice(separatorIndex + 1).trim());
  }

  return null;
}

export function issueAuthResponse<T extends { refreshToken: string }>(
  res: Response,
  payload: T,
): Omit<T, 'refreshToken'> {
  const { refreshToken, ...rest } = payload;
  setRefreshTokenCookie(res, refreshToken);
  return rest;
}
