import { randomUUID } from 'node:crypto';

import type { NextFunction, Request, Response } from 'express';

export interface RequestWithId extends Request {
  requestId?: string;
}

/**
 * Correlation ID en cada request. El cliente puede traer el suyo; si no, se
 * genera. Viaja de vuelta en el header y aparece en el cuerpo de los errores,
 * así quien reporta un problema tiene algo concreto que citar.
 *
 * El header entrante se acota a 128 caracteres: es un valor que después se
 * escribe en logs, y un header sin límite es una forma barata de inflarlos.
 */
export function requestIdMiddleware(req: RequestWithId, res: Response, next: NextFunction): void {
  const incoming = req.header('x-request-id');
  const requestId = incoming && incoming.length > 0 && incoming.length <= 128 ? incoming : randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
}
