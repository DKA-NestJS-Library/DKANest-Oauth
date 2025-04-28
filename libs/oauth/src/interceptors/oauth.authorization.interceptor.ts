import {
  BadGatewayException,
  BadRequestException,
  CallHandler,
  ExecutionContext,
  GatewayTimeoutException,
  Injectable,
  Logger,
  NestInterceptor,
  NotAcceptableException,
  OnModuleInit,
  PreconditionFailedException,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { ModuleRef, Reflector } from '@nestjs/core';
import * as fs from 'node:fs';
import { spawnSync } from 'child_process';
import * as path from 'node:path';
import * as os from 'node:os';
import * as process from 'node:process';
import { jwtDecrypt } from 'jose';
import { createPrivateKey } from 'node:crypto';
import { DEFINE_AUTHORIZATION_VERIFY } from '@app/oauth/decorators/oauth.authorization.decorator';

@Injectable()
export class OauthAuthorizationInterceptor
  implements NestInterceptor, OnModuleInit
{
  private readonly logger: Logger = new Logger(this.constructor.name);
  private KeyPath = path.join(`/var/tmp`, `${os.hostname()}`);

  constructor(
    private reflector: Reflector,
    private moduleRef: ModuleRef, // 👈 inject module ref
  ) {}

  async onModuleInit() {
    if (!fs.existsSync(this.KeyPath)) {
      this.logger.verbose(`Create Directory SSL for Encryption Token ...`);
      fs.mkdirSync(this.KeyPath, { recursive: true, mode: 0o755 });
      this.logger.log(
        'Creating RSA Private Key & RSA Public Key For Encryption Token...',
      );
      spawnSync(
        'openssl',
        [
          'genpkey',
          '-algorithm',
          'RSA',
          '-out',
          path.join(this.KeyPath, 'privkey.pem'),
          '-pkeyopt',
          'rsa_keygen_bits:8192',
        ],
        { stdio: 'inherit' },
      );
      spawnSync(
        'openssl',
        [
          'rsa',
          '-in',
          path.join(this.KeyPath, 'privkey.pem'),
          '-pubout',
          '-out',
          path.join(this.KeyPath, 'pubkey.pem'),
        ],
        { stdio: 'inherit' },
      );
    }
  }

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<any>> {
    const request = context.switchToHttp().getRequest();
    const { headers, url } = request;
    const method = request.method.toUpperCase();
    const scope = url.replace(/^\/|\/$/g, '').replace(/\//g, '.');
    const controllerClass = context.getClass();
    const handlerName = context.getHandler().name;

    if (!fs.existsSync(path.join(this.KeyPath, './privkey.pem')))
      return throwError(
        () =>
          new BadRequestException(`private key is missing, miss configured`),
      );

    const privateKey = fs.readFileSync(
      path.join(this.KeyPath, './privkey.pem'),
    );

    if (headers.authorization === undefined) {
      return throwError(
        () => new BadRequestException(`require header authorization`),
      );
    }
    /** Check Length Format Authorization is 2 with space  **/
    if (headers.authorization.split(' ').length !== 2) {
      return throwError(
        () =>
          new BadRequestException(
            `Illegal Index Format. Illegal Format Authorization`,
          ),
      );
    }

    /** Split To Array Authorization to Type and Token **/
    const [type, token] = headers.authorization.split(' ');
    /** check type Of Token **/
    if (type !== 'Bearer') {
      return throwError(
        () =>
          new BadRequestException(
            'The Type Token Must Bearer for Generated Token',
          ),
      );
    }

    return jwtDecrypt(token, createPrivateKey(privateKey), {
      subject: `${process.env.ACCESS_TOKEN_SUBJECT || 'access_token'}`,
      issuer: `${process.env.ACCESS_TOKEN_ISSUER || 'service-core-account'}`,
    })
      .then(({ payload }) => {
        SetMetadata(DEFINE_AUTHORIZATION_VERIFY, {
          ...payload,
          metadata: {
            method: method,
            action: handlerName,
            scope: scope,
          },
        })(context.getHandler());
        return next.handle();
      })
      .catch((error) => {
        switch (error.name) {
          case 'JWTExpired':
            return throwError(
              () => new UnauthorizedException('Token has expired.'),
            );
          case 'JWEDecryptionFailed':
            return throwError(
              () => new BadRequestException('Invalid or malformed token.'),
            );
          case 'NotBeforeError':
            return throwError(
              () => new NotAcceptableException('oken is not active yet.'),
            );
          case 'JsonWebTokenIssuerError':
            return throwError(
              () => new PreconditionFailedException('Invalid issuer.'),
            );
          case 'JsonWebTokenSubjectError':
            return throwError(
              () => new PreconditionFailedException('Invalid subject.'),
            );
          case 'JOSEAlgNotAllowed':
            return throwError(
              () => new PreconditionFailedException('Algorithm not allowed.'),
            );
          case 'JOSEError':
            return throwError(
              () => new PreconditionFailedException('JOSE error.'),
            );
          case 'JOSENotSupported':
            return throwError(
              () =>
                new PreconditionFailedException('JOSE format not supported.'),
            );
          case 'JWEInvalid':
            return throwError(
              () => new PreconditionFailedException('Invalid JWE.'),
            );
          case 'JWKInvalid':
            return throwError(
              () => new PreconditionFailedException('Invalid JWK'),
            );
          case 'JWKSInvalid':
            return throwError(
              () => new PreconditionFailedException('Invalid JWKS.'),
            );
          case 'JWKSMultipleMatchingKeys':
            return throwError(
              () =>
                new PreconditionFailedException(
                  'Multiple matching keys in JWKS..',
                ),
            );
          case 'JWKSNoMatchingKey':
            return throwError(
              () => new PreconditionFailedException('No matching key in JWKS.'),
            );
          case 'JWKSTimeout':
            return throwError(
              () => new GatewayTimeoutException('JWKS timeout.'),
            );
          case 'JWSInvalid':
            return throwError(() => new GatewayTimeoutException('Invalid JWS'));
          case 'JWSSignatureVerificationFailed':
            return throwError(
              () =>
                new PreconditionFailedException(
                  'JWS signature verification failed.',
                ),
            );
          case 'JWTClaimValidationFailed':
            return throwError(
              () =>
                new PreconditionFailedException('JWT claim validation failed.'),
            );
          case 'JWTInvalid':
            return throwError(
              () => new PreconditionFailedException('`Invalid JWT.'),
            );
          default:
            return throwError(
              () =>
                new BadGatewayException(
                  '`The token might be corrupted or incorrect.',
                ),
            );
        }
      });
  }
}
