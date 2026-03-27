/**
 * v1 editable avatar color regions (SVG layer keys).
 * Extend this list when new color slots are added; keep DB JSON merge-compatible.
 */
export const AVATAR_COLOR_KEYS = [
  'iris',
  'pupil',
  'hair',
  'skin',
  'lips',
  'nose',
  'earInner',
  'neck',
  'eyebrow',
  'outfit',
  'background',
] as const;

export type AvatarColorKey = (typeof AVATAR_COLOR_KEYS)[number];

export const DEFAULT_AVATAR_COLORS: Record<AvatarColorKey, string> = {
  iris: '#2d6e28',
  pupil: '#0e0500',
  hair: '#2e1f14',
  skin: '#e09868',
  lips: '#9a5028',
  nose: '#b87048',
  earInner: '#b87048',
  neck: '#e09868',
  eyebrow: '#2e1f14',
  outfit: '#2d3a4a',
  background: '#1a3842',
};
