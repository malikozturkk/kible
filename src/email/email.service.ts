import { Injectable } from '@nestjs/common';
import Mailjet from 'node-mailjet';

@Injectable()
export class EmailService {
  private readonly mailjet: Mailjet;

  private readonly senderEmail = process.env.MAILJET_SENDER_EMAIL;
  private readonly senderName = process.env.MAILJET_SENDER_NAME;
  private readonly templateId = Number(process.env.MAILJET_TEMPLATE_ID);

  constructor() {
    this.mailjet = new Mailjet({
      apiKey: process.env.MAILJET_API_KEY,
      apiSecret: process.env.MAILJET_API_SECRET,
    });
  }

  async sendTemplateEmail(
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
            TemplateID: this.templateId,
            TemplateLanguage: true,
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
