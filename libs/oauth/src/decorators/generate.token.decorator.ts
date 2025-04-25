// Custom decorator untuk scope dan actions
import { applyDecorators, SetMetadata, UseGuards } from '@nestjs/common';
import { ApiUnauthorizedResponse } from '@nestjs/swagger';
import { CreateTokenGuard } from '../guards/create.token.guard';
import { GenerateTokenCallback } from '../types/generate.token.type';

export const DEFINE_GENERATE_TOKEN_OAUTH_2_KEY = 'callback.oauth2.define';

export function GenerateToken() {
  return applyDecorators(
    UseGuards(CreateTokenGuard), // Menggunakan PathGuard
    ApiUnauthorizedResponse({ description: 'Unauthorized' }), // Respons Unauthorized
  );
}

// Custom decorator untuk scope dan actions
export function GenerateTokenResponse<ServiceClass>(
  callback: GenerateTokenCallback<ServiceClass>,
) {
  return applyDecorators(
    SetMetadata(DEFINE_GENERATE_TOKEN_OAUTH_2_KEY, callback),
  );
}
