import { Injectable } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { ReportClientErrorDto } from './dto/report-client-error.dto';

const USER_AGENT_MAX_LENGTH = 300;

@Injectable()
export class TelemetryService {
  constructor(private readonly logger: PinoLogger) {
    this.logger.setContext(TelemetryService.name);
  }

  recordClientError(report: ReportClientErrorDto, userAgent: string | undefined) {
    this.logger.error(
      {
        clientError: {
          source: report.source,
          url: report.url,
          digest: report.digest,
          stack: report.stack,
          userAgent: userAgent?.slice(0, USER_AGENT_MAX_LENGTH),
        },
      },
      `CLIENT_ERROR ${report.message}`,
    );
  }
}
