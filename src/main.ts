import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { FrontEnvs, PortEnvs } from './config';
import { Logger, ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AuthGuard } from 'nest-keycloak-connect';

async function bootstrap() {
  const logger = new Logger('Microservice-Gateway');

  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix('api');
  app.enableCors({
    origin: FrontEnvs.frontendServers,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS', // Añadir OPTIONS
    allowedHeaders: ['Content-Type', 'Authorization', 'credentials'],
    credentials: true, // Si estás utilizando cookies o encabezados de autenticación
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );
  // app.useGlobalGuards(app.get(RoleGuard));
  logger.log(`Gateway running on port ${PortEnvs.port}`);

  //Configuración swagger (Documentación de las APIS)
  const config = new DocumentBuilder()
    .setTitle('APIS DOCUMENTATION')
    .setDescription('Documentation of the Muserpol Microservices APIs')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.listen(PortEnvs.port);
}
bootstrap();
