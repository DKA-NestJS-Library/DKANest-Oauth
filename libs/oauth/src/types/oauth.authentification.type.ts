import { JWTPayload } from 'jose';

export type OauthAuthenticationMiddlewareCallback<ServiceClass> = (
  data: OauthAuthenticationCallbackData,
  ctx: ServiceClass,
) => JWTPayload | Error;

export interface OauthAuthenticationCallbackData {
  ClientID: string;
  ClientSecret: string;
  Scopes: Array<any>;
  Body: any;
}

export interface OauthAuthenticationConfig {
  ACCESS_TOKEN_AMOUNT?: number;
  ACCESS_TOKEN_UNIT?: string;
  REFRESH_TOKEN_AMOUNT?: number;
  REFRESH_TOKEN_UNIT?: string;
}
