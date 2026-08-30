import { IsArray, IsIn, IsISO8601, IsString, Matches, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import {
  LEGAL_DOCUMENT_KEYS,
  LEGAL_VERSION_PATTERN,
  type LegalDocumentKey,
} from '../legal.constants';

export class LegalDocumentDto {
  @IsIn([...LEGAL_DOCUMENT_KEYS])
  key: LegalDocumentKey;

  @IsString()
  @Matches(LEGAL_VERSION_PATTERN)
  version: string;

  @IsISO8601({ strict: true })
  effectiveDate: string;

  requiresConsentRecord: boolean;
}

export class LegalDocumentsResponseDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => LegalDocumentDto)
  documents: LegalDocumentDto[];
}
