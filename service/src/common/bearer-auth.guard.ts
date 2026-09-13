import { timingSafeEqual } from 'node:crypto';

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';

/**
 * Autenticación del demo: bearer token estático leído del entorno.
 *
 * En el servicio real esto valida un JWT contra el JWKS del IdP (firma, iss,
 * aud, exp, alg). La simplificación está declarada acá y en el threat model,
 * no escondida.
 *
 * Dos decisiones que sí son de producción:
 *  - Falla cerrado: sin token configurado devuelve 503 en vez de dejar pasar.
 *  - Compara en tiempo constante: una comparación con === filtra el token por
 *    diferencia de tiempo, y este guard protege el único endpoint de escritura.
 */
@Injectable()
export class BearerAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const expected = process.env.DEMO_API_TOKEN;
    if (!expected) {
      throw new ServiceUnavailableException('Service not configured');
    }

    const request = context.switchToHttp().getRequest<Request>();
    const header = request.header('authorization') ?? '';
    if (!header.startsWith('Bearer ')) {
      throw new UnauthorizedException('Unauthorized');
    }

    if (!this.constantTimeEquals(header.slice('Bearer '.length), expected)) {
      throw new UnauthorizedException('Unauthorized');
    }
    return true;
  }

  private constantTimeEquals(candidate: string, expected: string): boolean {
    const candidateBuffer = Buffer.from(candidate);
    const expectedBuffer = Buffer.from(expected);
    if (candidateBuffer.length !== expectedBuffer.length) {
      // timingSafeEqual exige el mismo largo. Comparar contra el esperado
      // consigo mismo mantiene el costo constante antes de devolver false.
      timingSafeEqual(expectedBuffer, expectedBuffer);
      return false;
    }
    return timingSafeEqual(candidateBuffer, expectedBuffer);
  }
}
