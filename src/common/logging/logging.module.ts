import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Module } from '@nestjs/common';
import { LoggerModule } from 'nestjs-pino';

const REQUEST_ID_HEADER = 'x-request-id';
const REQUEST_ID_PATTERN = /^[\w.-]{1,64}$/;

function resolveLogLevel(): string {
  if (process.env.LOG_LEVEL) return process.env.LOG_LEVEL;
  return process.env.NODE_ENV === 'production' ? 'info' : 'debug';
}

@Module({
  imports: [
    LoggerModule.forRoot({
      pinoHttp: {
        level: resolveLogLevel(),
        genReqId: (req: IncomingMessage, res: ServerResponse) => {
          const incoming = req.headers[REQUEST_ID_HEADER];
          const id =
            typeof incoming === 'string' && REQUEST_ID_PATTERN.test(incoming)
              ? incoming
              : randomUUID();
          res.setHeader('X-Request-Id', id);
          return id;
        },
        customLogLevel: (_req, res, err) => {
          if (err || res.statusCode >= 500) return 'error';
          if (res.statusCode >= 400) return 'warn';
          return 'info';
        },
        customProps: (req) => {
          const user = (req as IncomingMessage & { user?: { userId?: string } }).user;
          return user?.userId ? { userId: user.userId } : {};
        },
        serializers: {
          req: (req: { id: string; method: string; url: string; remoteAddress?: string }) => ({
            id: req.id,
            method: req.method,
            url: req.url,
            remoteAddress: req.remoteAddress,
          }),
          res: (res: { statusCode: number }) => ({ statusCode: res.statusCode }),
        },
        redact: {
          paths: [
            'req.headers.authorization',
            'req.headers.cookie',
            'res.headers["set-cookie"]',
            'req.body.password',
            'req.body.newPassword',
            'req.body.refreshToken',
            'req.body.token',
          ],
          censor: '[REDACTED]',
        },
        transport:
          process.env.NODE_ENV === 'production'
            ? undefined
            : {
                target: 'pino-pretty',
                options: {
                  colorize: true,
                  translateTime: 'SYS:HH:MM:ss.l',
                  singleLine: true,
                },
              },
      },
    }),
  ],
})
export class AppLoggingModule {}
