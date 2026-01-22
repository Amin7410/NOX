import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    // Enable CORS
    app.enableCors({
        origin: '*',
    });

    // Enable Global Validation
    app.useGlobalPipes(new ValidationPipe({
        whitelist: true,
        transform: true,
        forbidNonWhitelisted: true,
        exceptionFactory: (errors) => {
            console.error('[VALIDATION] Validation failed:', JSON.stringify(errors, null, 2));
            return new ValidationPipe().createExceptionFactory()(errors);
        },
    }));

    // Global prefix
    app.setGlobalPrefix('api/v1');

    await app.listen(3000);
    console.log(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();
