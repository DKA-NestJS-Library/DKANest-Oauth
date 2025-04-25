import { Injectable, Logger } from '@nestjs/common';
import { GenerateTokenResponse } from '@app/oauth';

@Injectable()
export class AppService {
  private readonly logger: Logger = new Logger(this.constructor.name);

  @GenerateTokenResponse<AppService>(({ ClientID, ClientSecret }, ctx) => {
    ctx.logger.log(ClientID, ClientSecret);
    return true;
  })
  getHello(): string {
    return 'Hello World!';
  }
}
