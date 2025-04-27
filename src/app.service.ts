import { Injectable, Logger } from '@nestjs/common';
import { OauthAuthenticationMiddlewares } from '@app/oauth';

@Injectable()
export class AppService {
  private readonly logger: Logger = new Logger(this.constructor.name);

  @OauthAuthenticationMiddlewares<AppService>(
    ({ ClientID, ClientSecret, Scopes }, ctx) => {
      return { halo: 123 };
    },
  )
  getHello2(tokenResult: string): string {
    return tokenResult;
  }
}
