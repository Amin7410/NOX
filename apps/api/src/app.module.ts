import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './modules/auth/auth.module';
import { RolesGuard } from './common/guards/api-auth.guard';
import { OrganizationsModule } from './modules/organizations/organizations.module';

@Module({
    imports: [ConfigModule.forRoot({ isGlobal: true }), AuthModule, OrganizationsModule],
    controllers: [],
    providers: [
        {
            provide: APP_GUARD,
            useClass: RolesGuard,
        },
    ],
})
export class AppModule { }
