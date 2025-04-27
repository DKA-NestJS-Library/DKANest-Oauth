// Custom decorator untuk scope dan actions
import {
  applyDecorators,
  createParamDecorator,
  ExecutionContext,
  SetMetadata,
  UseInterceptors,
} from '@nestjs/common';
import { ApiUnauthorizedResponse } from '@nestjs/swagger';
import {
  OauthAuthenticationConfig,
  OauthAuthenticationMiddlewareCallback,
} from '../types/oauth.authentification.type';
import { OauthAuthentificationInterceptor } from '../interceptors/oauth.authentification.interceptor';

export const DEFINE_GET_TOKEN_OAUTH_2_KEY = 'oauth2.get.token.define';
export const DEFINE_SET_CONFIG_TOKEN_OAUTH_2_KEY =
  'oauth2.set.config.token.define';
export const DEFINE_CALLBACK_TOKEN_OAUTH_2_MIDDLEWARE_KEY =
  'oauth2.callback.token.middleware.define';

export function OauthAuthentication() {
  return applyDecorators(
    UseInterceptors(OauthAuthentificationInterceptor), // Menggunakan PathGuard
    ApiUnauthorizedResponse({ description: 'Unauthorized' }), // Respons Unauthorized
  );
}

export function OauthAuthenticationMiddlewares<ClassName>(
  callback: OauthAuthenticationMiddlewareCallback<ClassName>,
) {
  return applyDecorators(
    SetMetadata(DEFINE_CALLBACK_TOKEN_OAUTH_2_MIDDLEWARE_KEY, callback),
  );
}

export function OauthAuthenticationSetTokenConfig(
  config: OauthAuthenticationConfig,
) {
  return applyDecorators(
    SetMetadata(DEFINE_SET_CONFIG_TOKEN_OAUTH_2_KEY, config),
    UseInterceptors(OauthAuthentificationInterceptor), // Menggunakan PathGuard
    ApiUnauthorizedResponse({ description: 'Unauthorized' }), // Respons Unauthorized
  );
}

// Custom decorator untuk scope dan actions
export function OauthAuthenticationResult(): any {
  return createParamDecorator((data: unknown, ctx: ExecutionContext) => {
    const handler = ctx.getHandler();
    return Reflect.getMetadata(DEFINE_GET_TOKEN_OAUTH_2_KEY, handler);
  })();
}
