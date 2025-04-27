import { Controller, Get, Logger, Post } from '@nestjs/common';
import { AppService } from './app.service';
import { OauthAuthentication, OauthAuthenticationResult } from '@app/oauth';
import {
  OauthAuthorizationResult,
  OauthAuthorizationVerify,
} from '@app/oauth/decorators/oauth.authorization.decorator';

@Controller()
export class AppController {
  private readonly logger: Logger = new Logger(this.constructor.name);
  constructor(private readonly appService: AppService) {}

  @Post('/')
  @OauthAuthentication()
  getHello(@OauthAuthenticationResult() tokenResult): string {
    return this.appService.getHello2(tokenResult);
  }

  @Get('/')
  @OauthAuthorizationVerify()
  verify(@OauthAuthorizationResult() sessionData) {
    return sessionData;
  }
}
