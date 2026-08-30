import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ConsentType } from '@prisma/client';
import {
  CONSENT_DOCUMENT_KEYS,
  LEGAL_CONFIG_KEY,
  LEGAL_DOCUMENT_KEYS,
  type LegalDocumentKey,
  type LegalDocumentsMap,
} from './legal.constants';
import { LegalDocumentDto, LegalDocumentsResponseDto } from './dto/legal-document.dto';
import type { ConsentVersionsMap } from '../consent/consent.constants';

@Injectable()
export class LegalService implements OnModuleInit {
  private readonly logger = new Logger(LegalService.name);

  constructor(private readonly config: ConfigService) {}

  onModuleInit() {
    const documents = this.getDocumentsMap();
    this.logger.log(
      `LEGAL_DOCUMENTS loaded: ${LEGAL_DOCUMENT_KEYS.map(
        (key) => `${key}=${documents[key].version}@${documents[key].effectiveDate}`,
      ).join(', ')}`,
    );
  }

  getDocumentsMap(): LegalDocumentsMap {
    const documents = this.config.get<LegalDocumentsMap>(LEGAL_CONFIG_KEY);
    if (!documents) {
      throw new Error('LEGAL_DOCUMENTS_NOT_CONFIGURED');
    }
    return documents;
  }

  getDocumentVersion(key: LegalDocumentKey): string {
    return this.getDocumentsMap()[key].version;
  }

  getConsentVersions(): ConsentVersionsMap {
    const documents = this.getDocumentsMap();
    const versions = {} as ConsentVersionsMap;
    for (const type of CONSENT_DOCUMENT_KEYS) {
      versions[type] = documents[type].version;
    }
    return versions;
  }

  listDocuments(): LegalDocumentsResponseDto {
    const documents = this.getDocumentsMap();

    const items: LegalDocumentDto[] = LEGAL_DOCUMENT_KEYS.map((key) => ({
      key,
      version: documents[key].version,
      effectiveDate: documents[key].effectiveDate,
      requiresConsentRecord: CONSENT_DOCUMENT_KEYS.includes(key as ConsentType),
    }));

    return { documents: items };
  }
}
