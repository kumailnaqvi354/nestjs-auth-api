import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [MongooseModule.forRoot("mongodb+srv://kumailali:Rendering14@cluster0.u7acins.mongodb.net/?retryWrites=true&w=majority"), UsersModule, AuthModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {
  
}
