import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { FrontEnvs, PortEnvs } from './config';
import { Logger, ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { NastEnvs } from './config';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import * as bodyParser from 'body-parser';
import * as cookieParser from 'cookie-parser';
async function bootstrap() {
  const logger = new Logger('Microservice-Gateway');

  const app = await NestFactory.create(AppModule);

  const microservice = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
    transport: Transport.NATS,
    options: {
      servers: NastEnvs.natsServers,
    },
  });

  await microservice.listen();

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
  app.use(cookieParser());
  app.use(bodyParser.json({ limit: '50mb' }));
  app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
  logger.log(`Gateway running on port ${PortEnvs.port}`);
  if (PortEnvs.environment === 'dev') {
    //Configuración swagger (Documentación de las APIS)
    const config = new DocumentBuilder()
      .setTitle('APIS DOCUMENTATION')
      .setDescription('Documentation of the Muserpol Microservices APIs')
      .setVersion('1.0')
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api', app, document);
  }
  await app.listen(PortEnvs.port);
}
bootstrap();
