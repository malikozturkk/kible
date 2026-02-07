import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { StringValue } from 'ms';
import { OtpService } from './otp.service';
import { OtpController } from './otp.controller';
import { OtpJwtGuard } from './guards/otp-jwt.guard';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [
    PrismaModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: {
        expiresIn: process.env.JWT_EXPIRES_IN as StringValue,
      },
    }),
  ],
  controllers: [OtpController],
  providers: [OtpService, OtpJwtGuard],
  exports: [OtpService],
})
export class OtpModule {}
