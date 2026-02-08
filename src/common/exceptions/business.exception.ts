import { HttpException, HttpStatus } from '@nestjs/common';

export class BusinessException extends HttpException {
  public readonly messageKey: string;
  public readonly errorCode: number;
  public readonly attachment: string | null;

  constructor(
    messageKey: string,
    httpStatus: HttpStatus = HttpStatus.BAD_REQUEST,
    attachment: string | null = null,
  ) {
    super(messageKey, httpStatus);
    this.messageKey = messageKey;
    this.errorCode = httpStatus;
    this.attachment = attachment;
  }
}
