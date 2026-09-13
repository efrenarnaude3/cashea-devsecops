import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';

import { AppModule } from '../src/app.module';
import { configureApp } from '../src/main';
import { NotesService } from '../src/notes/notes.service';

/**
 * Cada test afirma una propiedad de seguridad del servicio, no que el endpoint
 * devuelva 200. Son los tests que detectan una regresión en los controles que
 * describe docs/security-gates.md.
 *
 * Corren contra la misma configuración que se despliega, porque usan
 * configureApp() en vez de rearmar la app a mano.
 */
const TOKEN = 'test-token-not-a-real-credential';
const AUTH = { Authorization: `Bearer ${TOKEN}` };

describe('notes-api (propiedades de seguridad)', () => {
  let app: INestApplication;
  let notes: NotesService;

  beforeAll(async () => {
    process.env.DEMO_API_TOKEN = TOKEN;
    process.env.ALLOWED_ORIGINS = 'http://localhost:3000';

    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    configureApp(app);
    await app.init();
    notes = moduleRef.get(NotesService);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    notes.clear();
  });

  describe('health', () => {
    it('liveness es público y responde ok', async () => {
      const res = await request(app.getHttpServer()).get('/health');
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 'ok' });
    });

    it('readiness es público', async () => {
      const res = await request(app.getHttpServer()).get('/health/ready');
      expect(res.status).toBe(200);
    });
  });

  describe('headers de seguridad', () => {
    it('manda los headers que el gate de DAST verifica', async () => {
      const res = await request(app.getHttpServer()).get('/health');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('DENY');
      expect(res.headers['referrer-policy']).toBe('no-referrer');
      expect(res.headers['content-security-policy']).toContain("default-src 'none'");
      expect(res.headers['x-request-id']).toBeTruthy();
    });

    it('devuelve el request id que mandó el cliente', async () => {
      const res = await request(app.getHttpServer()).get('/health').set('X-Request-ID', 'abc-123');
      expect(res.headers['x-request-id']).toBe('abc-123');
    });
  });

  describe('autenticación del endpoint de escritura', () => {
    it('rechaza sin token y no filtra detalle interno', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/notes')
        .send({ title: 'a', body: 'b' });

      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Unauthorized');
      expect(res.body.requestId).toBeTruthy();
      expect(JSON.stringify(res.body)).not.toContain('stack');
    });

    it('rechaza un token equivocado', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/notes')
        .set({ Authorization: 'Bearer wrong-token' })
        .send({ title: 'a', body: 'b' });

      expect(res.status).toBe(401);
    });
  });

  describe('validación de entrada', () => {
    it('rechaza campos no declarados (anti mass assignment)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/notes')
        .set(AUTH)
        .send({ title: 'a', body: 'b', isAdmin: true });

      expect(res.status).toBe(400);
    });

    it('aplica el límite de largo del título', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/notes')
        .set(AUTH)
        .send({ title: 'x'.repeat(121), body: 'b' });

      expect(res.status).toBe(400);
    });

    it('rechaza un limit fuera de rango', async () => {
      const res = await request(app.getHttpServer()).get('/api/v1/notes').query({ limit: 1000 });
      expect(res.status).toBe(400);
    });

    it('rechaza un query param no declarado', async () => {
      const res = await request(app.getHttpServer()).get('/api/v1/notes').query({ sortBy: 'title' });
      expect(res.status).toBe(400);
    });
  });

  describe('identificadores', () => {
    it('crea y lee de vuelta', async () => {
      const created = await request(app.getHttpServer())
        .post('/api/v1/notes')
        .set(AUTH)
        .send({ title: 'hola', body: 'mundo' });

      expect(created.status).toBe(201);
      const id: string = created.body.id;

      const fetched = await request(app.getHttpServer()).get(`/api/v1/notes/${id}`);
      expect(fetched.status).toBe(200);
      expect(fetched.body.title).toBe('hola');
    });

    it('un id que no es UUID no llega al store', async () => {
      const res = await request(app.getHttpServer()).get('/api/v1/notes/1');
      expect(res.status).toBe(400);
    });

    it('un UUID inexistente es 404', async () => {
      const res = await request(app.getHttpServer()).get(
        '/api/v1/notes/11111111-1111-4111-8111-111111111111',
      );
      expect(res.status).toBe(404);
    });
  });

  describe('errores', () => {
    it('una ruta desconocida devuelve el mismo sobre de error', async () => {
      const res = await request(app.getHttpServer()).get('/no-existe');
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('statusCode', 404);
      expect(res.body).toHaveProperty('requestId');
    });
  });

  // Va último a propósito: el contador del throttler es por proceso y no se
  // reinicia entre tests. El loop con tope afirma la propiedad ("el límite
  // engancha") sin depender de cuántos POST hicieron los tests anteriores.
  describe('rate limiting', () => {
    it('termina devolviendo 429 en el endpoint de escritura', async () => {
      const statuses: number[] = [];

      for (let i = 0; i < 25; i += 1) {
        const res = await request(app.getHttpServer())
          .post('/api/v1/notes')
          .set(AUTH)
          .send({ title: `flood-${i}`, body: 'b' });
        statuses.push(res.status);
        if (res.status === 429) {
          break;
        }
      }

      expect(statuses).toContain(429);
    });
  });
});
