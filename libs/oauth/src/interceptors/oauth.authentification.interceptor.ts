import {
  BadGatewayException,
  BadRequestException,
  CallHandler,
  ExecutionContext,
  Injectable,
  InternalServerErrorException,
  Logger,
  NestInterceptor,
  OnModuleInit,
  SetMetadata,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import validator from 'validator';
import {
  DEFINE_CALLBACK_TOKEN_OAUTH_2_MIDDLEWARE_KEY,
  DEFINE_GET_TOKEN_OAUTH_2_KEY,
} from '../decorators/oauth.authentification.decorator';
import { ModuleRef, Reflector } from '@nestjs/core';
import * as fs from 'node:fs';
import { spawnSync } from 'child_process';
import * as path from 'node:path';
import * as os from 'node:os';
import * as process from 'node:process';
import * as moment from 'moment-timezone';
import { DurationInputArg2 } from 'moment-timezone';
import { EncryptJWT } from 'jose';
import { createPublicKey } from 'crypto';

@Injectable()
export class OauthAuthentificationInterceptor
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
    const { headers, body, url } = request;
    const Body = body;
    const scope = url.replace(/^\/|\/$/g, '').replace(/\//g, '.');
    const method = request.method.toUpperCase();

    const controllerClass = context.getClass();
    const handlerName = context.getHandler().name;

    if (!fs.existsSync(path.join(this.KeyPath, './pubkey.pem')))
      return throwError(
        () =>
          new InternalServerErrorException(
            'Public key is missing, miss configured.',
          ),
      );

    const publicKey = fs.readFileSync(path.join(this.KeyPath, './pubkey.pem'));

    /** Mengecek Apakah Method Digunakan Decorator Adalah Post dan wajib post **/
    if (method !== 'POST') {
      return throwError(
        () => new BadGatewayException('endpoint token must post method'),
      );
    }

    if (body.grant_type === undefined) {
      return throwError(
        () =>
          new BadGatewayException(
            'body grant type must exist. is body grant type is undefined',
          ),
      );
    }

    switch (body.grant_type) {
      case 'client_credentials':
        /** Check Header Authorization Not Undefined**/
        if (headers.authorization === undefined) {
          return throwError(
            () =>
              new BadRequestException(
                `on ${body.grant_type} require header authorization`,
              ),
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
        if (type !== 'Basic') {
          return throwError(
            () =>
              new BadRequestException(
                'The Type Token Must Basic for Generated Token',
              ),
          );
        }
        /** Check Token Is Base64 **/
        if (!validator.isBase64(token)) {
          return throwError(
            () => new BadRequestException('The Token Must Base64 Format'),
          );
        }
        /** Convert Base64 To String Raw **/
        const tokenizer = Buffer.from(token, 'base64').toString('utf-8');

        /** Check Length Format Tokenizer is 2 with :  **/
        if (tokenizer.split(':').length !== 2) {
          return throwError(
            () =>
              new BadRequestException(
                `Illegal Index Format. Illegal Format Tokenizer`,
              ),
          );
        }
        /** Split To Array Tokenizer to ClientID and ClientSecret **/
        const [ClientID, ClientSecret] = tokenizer.split(':');

        // 💡 Ambil instance controller
        const controllerInstance = this.moduleRef.get(controllerClass, {
          strict: false,
        });

        if (!controllerInstance) {
          return throwError(
            () =>
              new InternalServerErrorException('Controller instance not found'),
          );
        }

        const { methodName } = this.extractServiceMethodName(
          controllerInstance,
          handlerName,
        );

        // 💡 Cari semua properti di controller yang merupakan instance service
        const serviceInstance = Object.values(controllerInstance).find(
          (value) =>
            typeof value === 'object' && value !== null && value[methodName],
        );

        if (!serviceInstance) {
          throw new InternalServerErrorException(
            'Service method not found in controller instance.',
          );
        }

        // 💡 Ambil method service-nya
        const serviceMethod = serviceInstance[methodName];

        const callback = Reflect.getMetadata(
          DEFINE_CALLBACK_TOKEN_OAUTH_2_MIDDLEWARE_KEY,
          serviceMethod,
        );

        if (!callback) {
          throw new InternalServerErrorException(
            `Callback Middleware Not Exist. use @OauthGetTokenMiddlewares on ${handlerName} method`,
          );
        }

        const scopesRaw = body.scope !== undefined ? body.scope.split(',') : [];

        const Scopes = scopesRaw.map((item) => {
          const [scope, action] = item.split(':').map((part) => part.trim());
          return { scope, action };
        });

        const payload = callback(
          {
            ClientID,
            ClientSecret,
            Scopes,
            Body,
          },
          serviceInstance,
        );

        if (payload instanceof Error) {
          return throwError(() => payload);
        }

        const timeNow = moment(moment.now());

        const AccessTokenExpires = timeNow
          .clone()
          .add(
            Number(`${process.env.ACCESS_TOKEN_EXPIRES_AMOUNT || 5}`),
            `${(process.env.ACCESS_TOKEN_EXPIRES_UNIT as DurationInputArg2) || 'minutes'}`,
          );
        const RefreshTokenExpires = timeNow
          .clone()
          .add(
            Number(`${process.env.REFRESH_TOKEN_EXPIRES_AMOUNT || 1}`),
            `${(process.env.REFRESH_TOKEN_EXPIRES_UNIT as DurationInputArg2) || 'days'}`,
          );

        const AccessToken = new EncryptJWT({
          ...payload,
        })
          .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
          .setExpirationTime(AccessTokenExpires.unix())
          .setIssuer(
            `${process.env.ACCESS_TOKEN_ISSUER || 'service-core-account'}`,
          )
          .setSubject(`${process.env.ACCESS_TOKEN_SUBJECT || 'access_token'}`);

        const RefreshToken = new EncryptJWT({
          ...payload,
        })
          .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
          .setExpirationTime(RefreshTokenExpires.unix())
          .setIssuer(
            `${process.env.REFRESH_TOKEN_ISSUER || 'service-core-account'}`,
          )
          .setSubject(
            `${process.env.REFRESH_TOKEN_SUBJECT || 'refresh_token'}`,
          );

        return Promise.all([
          AccessToken.encrypt(createPublicKey(publicKey)),
          RefreshToken.encrypt(createPublicKey(publicKey)),
        ])
          .then(async ([accessToken, refreshToken]: any) => {
            SetMetadata(DEFINE_GET_TOKEN_OAUTH_2_KEY, {
              token_type: 'Bearer',
              access_token: `${accessToken}`,
              refresh_token: `${refreshToken}`,
              expires_in: moment
                .duration(AccessTokenExpires.diff(timeNow))
                .asSeconds(),
            })(context.getHandler());
            return next.handle();
          })
          .catch((error) => {
            this.logger.error(error);
            return throwError(
              () =>
                new InternalServerErrorException(
                  'Failed To Generate Access Token / Refresh Token',
                ),
            );
          });
      default:
        return throwError(() => new BadGatewayException());
    }
  }

  private extractServiceMethodName(
    controllerInstance: any,
    handlerName: string,
  ) {
    const handler = controllerInstance[handlerName];

    if (typeof handler !== 'function') {
      throw new Error('Handler is not a function.');
    }

    const tracker = {
      serviceCall: null as null | { serviceName: string; methodName: string },

      wrapService(serviceName: string, serviceInstance: any) {
        return new Proxy(serviceInstance, {
          get(target, prop: string) {
            if (typeof target[prop] === 'function') {
              if (!tracker.serviceCall) {
                tracker.serviceCall = { serviceName, methodName: prop };
              }
              return () => {}; // dummy function, no real call
            }
            return target[prop];
          },
        });
      },
    };

    // Bikin proxy this
    const fakeThis: Record<string, any> = {};

    for (const key of Object.keys(controllerInstance)) {
      if (
        typeof controllerInstance[key] === 'object' &&
        controllerInstance[key] !== null
      ) {
        fakeThis[key] = tracker.wrapService(key, controllerInstance[key]);
      } else {
        fakeThis[key] = controllerInstance[key];
      }
    }

    const fakeHandler = handler.bind(fakeThis);

    try {
      fakeHandler(); // panggil dengan this palsu
    } catch (err) {
      // cuekin error
      throw new InternalServerErrorException(err);
    }

    return tracker.serviceCall; // { serviceName: 'appService', methodName: 'getHello' }
  }
}
