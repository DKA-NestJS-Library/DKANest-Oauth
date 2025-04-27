import {
  applyDecorators,
  createParamDecorator,
  ExecutionContext,
  UseInterceptors,
} from '@nestjs/common';
import { ApiUnauthorizedResponse } from '@nestjs/swagger';
import { OauthAuthorizationInterceptor } from '../interceptors/oauth.authorization.interceptor';

export const DEFINE_AUTHORIZATION_VERIFY = 'oauth2.authorization.verify.define';

export function OauthAuthorizationVerify() {
  return applyDecorators(
    UseInterceptors(OauthAuthorizationInterceptor), // Menggunakan PathGuard
    ApiUnauthorizedResponse({ description: 'Unauthorized' }), // Respons Unauthorized
  );
}

// Custom decorator untuk scope dan actions
export function OauthAuthorizationResult(): any {
  return createParamDecorator((data: unknown, ctx: ExecutionContext) => {
    const handler = ctx.getHandler();
    return Reflect.getMetadata(DEFINE_AUTHORIZATION_VERIFY, handler);
  })();
}
