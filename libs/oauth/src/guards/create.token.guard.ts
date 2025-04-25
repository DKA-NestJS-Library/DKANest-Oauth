import {
  BadGatewayException,
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import validator from 'validator';
import { ModuleRef, Reflector } from '@nestjs/core';
import { DEFINE_GENERATE_TOKEN_OAUTH_2_KEY } from '../decorators/generate.token.decorator';
import { GenerateTokenCallbackData } from '../types/generate.token.type';

@Injectable()
export class CreateTokenGuard implements CanActivate {
  private readonly logger: Logger = new Logger(this.constructor.name);
  constructor(
    private reflector: Reflector,
    private moduleRef: ModuleRef, // 👈 inject module ref
  ) {}

  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const { url, headers, body } = request;
    const method = request.method.toUpperCase();
    const name = context.getHandler().name;
    const scope = url.replace(/^\/|\/$/g, '').replace(/\//g, '.');

    const controllerClass = context.getClass();
    const handlerName = context.getHandler().name;

    /** Mengecek Apakah Method Digunakan Decorator Adalah Post dan wajib post **/
    if (method !== 'POST') {
      throw new BadGatewayException('endpoint token must post method');
    }

    if (body.grant_type === undefined) {
      throw new BadGatewayException(
        'body grant type must exist. is body grant type is undefined',
      );
    }

    switch (body.grant_type) {
      case 'client_credentials':
        /** Check Header Authorization Not Undefined**/
        if (headers.authorization === undefined) {
          throw new BadRequestException(
            `on ${body.grant_type} require header authorization`,
          );
        }
        /** Check Length Format Authorization is 2 with space  **/
        if (headers.authorization.split(' ').length !== 2) {
          throw new BadRequestException(
            `Illegal Index Format. Illegal Format Authorization`,
          );
        }

        /** Split To Array Authorization to Type and Token **/
        const [type, token] = headers.authorization.split(' ');
        /** check type Of Token **/
        if (type !== 'Basic') {
          throw new BadRequestException(
            'The Type Token Must Basic for Generated Token',
          );
        }
        /** Check Token Is Base64 **/
        if (!validator.isBase64(token)) {
          throw new BadRequestException('The Token Must Base64 Format');
        }
        /** Convert Base64 To String Raw **/
        const tokenizer = Buffer.from(token, 'base64').toString('utf-8');

        /** Check Length Format Tokenizer is 2 with :  **/
        if (tokenizer.split(':').length !== 2) {
          throw new BadRequestException(
            `Illegal Index Format. Illegal Format Tokenizer`,
          );
        }
        /** Split To Array Tokenizer to ClientID and ClientSecret **/
        const [ClientID, ClientSecret] = tokenizer.split(':');

        /** 💡 Ambil instance controller **/
        const controllerInstance = this.moduleRef.get(controllerClass, {
          strict: false,
        });
        /** 💡 Check Controller Instances **/
        if (!controllerInstance) {
          throw new InternalServerErrorException(
            'Controller instance not found',
          );
        }

        // 💡 Cari semua properti di controller yang merupakan instance service
        const serviceInstance = Object.values(controllerInstance).find(
          (value) =>
            typeof value === 'object' && value !== null && value[handlerName],
        );

        if (!serviceInstance) {
          throw new InternalServerErrorException(
            'Service method not found in controller instance.',
          );
        }

        // 💡 Ambil method service-nya
        const serviceMethod = serviceInstance[handlerName];
        const callback = Reflect.getMetadata(
          DEFINE_GENERATE_TOKEN_OAUTH_2_KEY,
          serviceMethod,
        );

        if (!callback) {
          throw new InternalServerErrorException(
            'Generate Token callback not defined in service method.',
          );
        }

        const UsersCallbackToken: GenerateTokenCallbackData = callback(
          { ClientID, ClientSecret },
          serviceInstance,
        );
        response.status(200).send({ success: true});
        break;
    }

    return true;
  }
}
