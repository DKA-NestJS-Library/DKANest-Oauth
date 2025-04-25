import { Controller, Get, Post } from '@nestjs/common';
import { AppService } from './app.service';
import { GenerateToken } from '@app/oauth';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post()
  @GenerateToken()
  getHello(): string {
    return this.appService.getHello();
  }
}
