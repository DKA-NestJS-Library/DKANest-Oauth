
<h1 align="center">
The Library Privileges Oauth2 Authentification & Authorization
</h1>


<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

<p align="center">
    <a href="https://www.npmjs.com/package/@dkanest/oauth" target="_blank"><img src="https://img.shields.io/npm/v/@dkanest/oauth.svg" alt="NPM Version" /></a>
    <a href="https://www.npmjs.com/package/@dkanest/oauth" target="_blank"><img src="https://img.shields.io/npm/l/@dkanest/oauth.svg" alt="Package License" /></a>
    <a href="https://www.npmjs.com/package/@dkanest/oauth" target="_blank"><img src="https://img.shields.io/npm/dm/@dkanest/oauth.svg" alt="NPM Downloads" /></a>
</p>

## Description

The Library NestJS Oauth Authentification & Authorization

## Controller

```ts
import { Controller, Get, Post } from '@nestjs/common';
import { AppService } from './app.service';
import { OauthAuthentication, OauthAuthenticationResult } from '@dkanest/oauth';
import {
  OauthAuthorizationResult,
  OauthAuthorizationVerify,
} from '@app/oauth/decorators/oauth.authorization.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post('/')
  /**
   * Authomatically create Token Binding to Anotation @OauthAuthenticationMiddlewares in Hello2Service Method
   */
  @OauthAuthentication()
  /** The Result Tokent With @OauthAuthenticationResult **/
  getHello(@OauthAuthenticationResult() tokenResult): string {
    return this.appService.getHello2(tokenResult);
  }

  @Get('/')
  @OauthAuthorizationVerify()
  /** Automatically Verification And Get Payload Decrypted Token to Session Data **/
  read(@OauthAuthorizationResult() sessionData) {
    return sessionData;
  }
}


```

## Service Binding

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { OauthAuthenticationMiddlewares } from '@dkanest/oauth';

@Injectable()
export class AppService {
  private readonly logger: Logger = new Logger(this.constructor.name);

  @OauthAuthenticationMiddlewares<AppService>(
    ({ ClientID, ClientSecret, Scopes, Body }, ctx) => {
      //ctx.logger.log(`Ini adalah ctx dari this class ini`)
      /**
       * Return Berisi payload Yang Akan Di Encrypt Menjadi Token Di Controller ResultToken
       */
      return { halo: 123 };
    },
  )
  getHello2(tokenResult: string): string {
    return tokenResult;
  }
}

```
