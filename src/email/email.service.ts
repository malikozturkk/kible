import { Injectable } from '@nestjs/common';
import Mailjet from 'node-mailjet';

@Injectable()
export class EmailService {
  private readonly mailjet: Mailjet;

  private readonly senderEmail = process.env.MAILJET_SENDER_EMAIL;
  private readonly senderName = process.env.MAILJET_SENDER_NAME;
  private readonly otpTemplateId = Number(process.env.MAILJET_OTP_TEMPLATE_ID);
  private readonly forgotPasswordTemplateId = Number(
    process.env.MAILJET_FORGOT_PASSWORD_TEMPLATE_ID,
  );

  constructor() {
    this.mailjet = new Mailjet({
      apiKey: process.env.MAILJET_API_KEY,
      apiSecret: process.env.MAILJET_API_SECRET,
    });
  }

  async sendOtpEmail(
    toEmail: string,
    toName: string,
    variables: Record<string, any>,
  ): Promise<void> {
    try {
      const result = await this.mailjet.post('send', { version: 'v3.1' }).request({
        Messages: [
          {
            From: {
              Email: this.senderEmail,
              Name: this.senderName,
            },
            To: [
              {
                Email: toEmail,
                Name: toName,
              },
            ],
            Subject: 'NamazGo Hesap Doğrulama Kodunuz',
            TemplateID: this.otpTemplateId,
            TemplateLanguage: true,
            TextPart: `Merhaba ${toName}, NamazGo hesap doğrulama kodunuz: ${variables.code}. Bu kod 3 dakika geçerlidir.`,
            Variables: { ...variables, username: toName },
          },
        ],
      });

      console.log(`E-posta başarıyla gönderildi: ${toEmail}`);
      console.debug(`Mailjet yanıtı: ${JSON.stringify(result.body)}`);
    } catch (error: any) {
      console.error(`E-posta gönderimi başarısız: ${toEmail}`, error?.stack || error?.message);
      throw error;
    }
  }

  async sendForgotPasswordEmail(
    toEmail: string,
    toName: string,
    variables: Record<string, any>,
  ): Promise<void> {
    try {
      const result = await this.mailjet.post('send', { version: 'v3.1' }).request({
        Messages: [
          {
            From: {
              Email: this.senderEmail,
              Name: this.senderName,
            },
            To: [
              {
                Email: toEmail,
                Name: toName,
              },
            ],
            Subject: 'NamazGo Parola Sıfırlama Talebiniz',
            TemplateID: this.forgotPasswordTemplateId,
            TemplateLanguage: true,
            TextPart: `Merhaba ${toName}, NamazGo hesabınız için bir parola sıfırlama talebi aldık. Parolanızı sıfırlamak için e-posta içeriğindeki bağlantıyı kullanabilirsiniz. Eğer bu talebi siz yapmadıysanız, bu mesajı dikkate almayabilirsiniz.`,
            Variables: { ...variables, username: toName },
          },
        ],
      });

      console.log(`E-posta başarıyla gönderildi: ${toEmail}`);
      console.debug(`Mailjet yanıtı: ${JSON.stringify(result.body)}`);
    } catch (error: any) {
      console.error(`E-posta gönderimi başarısız: ${toEmail}`, error?.stack || error?.message);
      throw error;
    }
  }
}
