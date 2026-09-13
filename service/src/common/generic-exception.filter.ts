import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import type { Request, Response } from 'express';

interface ErrorEnvelope {
  message: string;
  statusCode: number;
  requestId: string | null;
}

/**
 * Un solo sobre de error para toda la API.
 *
 * 4xx puede llevar mensaje específico: el cliente necesita saber qué mandó mal.
 * 5xx nunca: el detalle va al log del servidor y al cliente le llega un mensaje
 * genérico más el requestId para poder rastrearlo. Un stack trace en la
 * respuesta es reconocimiento gratis para quien esté probando la API.
 */
@Catch()
export class GenericExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GenericExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request & { requestId?: string }>();
    const requestId = request.requestId ?? null;

    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body: ErrorEnvelope = {
        message: this.extractMessage(exception),
        statusCode: status,
        requestId,
      };
      response.status(status).json(body);
      return;
    }

    this.logger.error(
      JSON.stringify({
        event: 'unhandled_exception',
        method: request.method,
        path: request.url,
        requestId,
      }),
      exception instanceof Error ? exception.stack : undefined,
    );

    const body: ErrorEnvelope = {
      message: 'Internal server error',
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      requestId,
    };
    response.status(HttpStatus.INTERNAL_SERVER_ERROR).json(body);
  }

  private extractMessage(exception: HttpException): string {
    const payload = exception.getResponse();
    if (typeof payload === 'string') {
      return payload;
    }
    const message = (payload as { message?: string | string[] }).message;
    if (Array.isArray(message)) {
      return message.join('; ');
    }
    return message ?? exception.message;
  }
}
