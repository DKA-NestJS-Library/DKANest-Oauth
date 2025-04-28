
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
import { Privileges } from '@dkanest/oauth';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Privileges()
  getHello(): string {
    return this.appService.getHello();
  }
}

```

## Service Binding

```typescript
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { AccessPrivileges } from '@dkanest/privileges';

@Injectable()
export class AppService {
  private readonly logger: Logger = new Logger(this.constructor.name);

  /**
   * @param {string} scope adalah url yang berupa format (.) dot
   * @param {string} name nama method yang di controller
   * @param { string } method method yang digunakan di controller @Get(), @Post() etc
   * @return { boolean } jika false maka akan mengembalikan unauthorization, jika true maka di izinkan
   * **/
  @AccessPrivileges<AppService>(({ scope, method, name }, ctx) => {
    return scope === 'halo.apa' && name === 'getHello';
  })
  getHello(): string {
    return 'Hello World!';
  }

}
```
