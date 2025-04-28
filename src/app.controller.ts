import { Controller, Get, Post } from '@nestjs/common';
import { AppService } from './app.service';
import { OauthAuthentication, OauthAuthenticationResult } from '@app/oauth';
import {
  OauthAuthorizationResult,
  OauthAuthorizationVerify,
} from '@app/oauth/decorators/oauth.authorization.decorator';

@Controller('/auth')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post('/')
  @OauthAuthentication()
  getHello(@OauthAuthenticationResult() tokenResult): string {
    return this.appService.getHello2(tokenResult);
  }

  @Get('/')
  @OauthAuthorizationVerify()
  read(@OauthAuthorizationResult() sessionData) {
    return sessionData;
  }
}
