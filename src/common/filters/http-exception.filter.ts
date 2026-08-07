import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ApiResponse } from '../interfaces/api-response.interface.js';
import { BusinessException } from '../exceptions/business.exception.js';

const DEFAULT_MESSAGE_KEYS: Record<number, string> = {
  [HttpStatus.BAD_REQUEST]: 'BAD_REQUEST',
  [HttpStatus.UNAUTHORIZED]: 'UNAUTHORIZED',
  [HttpStatus.FORBIDDEN]: 'FORBIDDEN',
  [HttpStatus.NOT_FOUND]: 'NOT_FOUND',
  [HttpStatus.METHOD_NOT_ALLOWED]: 'METHOD_NOT_ALLOWED',
  [HttpStatus.CONFLICT]: 'CONFLICT',
  [HttpStatus.UNPROCESSABLE_ENTITY]: 'UNPROCESSABLE_ENTITY',
  [HttpStatus.TOO_MANY_REQUESTS]: 'TOO_MANY_REQUESTS',
  [HttpStatus.INTERNAL_SERVER_ERROR]: 'INTERNAL_SERVER_ERROR',
};

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
    let messageKey = 'INTERNAL_SERVER_ERROR';
    let attachment: string | null = null;

    if (exception instanceof BusinessException) {
      httpStatus = exception.getStatus();
      messageKey = exception.messageKey;
      attachment = exception.attachment;
    } else if (exception instanceof HttpException) {
      httpStatus = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'string') {
        messageKey = this.normalizeMessageKey(exceptionResponse, httpStatus);
      } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const resp = exceptionResponse as Record<string, any>;

        if (Array.isArray(resp.message)) {
          messageKey = 'VALIDATION_ERROR';
          attachment = resp.message.join('; ');
        } else if (typeof resp.message === 'string') {
          messageKey = this.normalizeMessageKey(resp.message, httpStatus);
        } else {
          messageKey = DEFAULT_MESSAGE_KEYS[httpStatus] || 'UNKNOWN_ERROR';
        }
      }
    }

    this.logUnexpected(exception, httpStatus, request);

    const errorResponse: ApiResponse = {
      date: Date.now(),
      success: false,
      data: null,
      error: {
        code: httpStatus,
        message: messageKey,
        attachment,
      },
    };

    response.status(httpStatus).json(errorResponse);
  }

  private logUnexpected(exception: unknown, httpStatus: number, request: Request) {
    if (exception instanceof BusinessException) return;
    if (exception instanceof HttpException && httpStatus < 500) {
      return;
    }

    const requestId = typeof request.id === 'string' ? request.id : undefined;
    const context = `${request.method} ${request.url}${requestId ? ` reqId=${requestId}` : ''}`;

    if (exception instanceof Error) {
      this.logger.error(`${context} → ${httpStatus} ${exception.message}`, exception.stack);
    } else {
      this.logger.error(`${context} → ${httpStatus} non-Error thrown: ${String(exception)}`);
    }
  }

  private normalizeMessageKey(message: string, httpStatus: number): string {
    if (/^[A-Z][A-Z0-9_]*$/.test(message)) {
      return message;
    }

    return DEFAULT_MESSAGE_KEYS[httpStatus] || 'UNKNOWN_ERROR';
  }
}
