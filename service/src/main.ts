import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';

import { AppModule } from './app.module';
import { GenericExceptionFilter } from './common/generic-exception.filter';
import { requestIdMiddleware } from './common/request-id.middleware';

/**
 * Toda la configuración de seguridad del proceso vive acá, en una función que
 * usan tanto el arranque real como los tests. Si estuviera solo en bootstrap(),
 * los tests correrían contra una app distinta de la que se despliega, y los
 * headers que afirman verificar no probarían nada.
 */
export function configureApp(app: INestApplication): void {
  // CSP en default-src 'none' porque esto es una API: no sirve HTML y no
  // debería poder cargar ningún recurso.
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: { 'default-src': ["'none'"], 'frame-ancestors': ["'none'"] },
      },
      frameguard: { action: 'deny' },
      referrerPolicy: { policy: 'no-referrer' },
      hsts: { maxAge: 63072000, includeSubDomains: true },
    }),
  );
  app.use(requestIdMiddleware);

  // CORS con lista explícita. Sin ALLOWED_ORIGINS queda apagado, que es el
  // default seguro: un origen no declarado no entra.
  const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  if (allowedOrigins.length > 0) {
    app.enableCors({
      origin: allowedOrigins,
      credentials: true,
      methods: ['GET', 'POST'],
      allowedHeaders: ['Authorization', 'Content-Type', 'X-Request-ID'],
    });
  }

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // descarta lo que no está declarado en el DTO
      forbidNonWhitelisted: true, // y además lo rechaza con 400
      transform: true,
      transformOptions: { enableImplicitConversion: false },
    }),
  );
  app.useGlobalFilters(new GenericExceptionFilter());
  app.enableShutdownHooks();
}

/**
 * Contrato de Cloud Run: el contenedor escucha en process.env.PORT y bindea
 * 0.0.0.0. Es el mismo contrato de un Pod, así que el binario corre sin
 * cambios en Cloud Run, en kind y en `docker run`.
 */
async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  configureApp(app);
  const port = Number(process.env.PORT ?? 8080);
  await app.listen(port, '0.0.0.0');
}

// No arranca el server cuando el módulo se importa desde los tests.
if (require.main === module) {
  void bootstrap();
}
