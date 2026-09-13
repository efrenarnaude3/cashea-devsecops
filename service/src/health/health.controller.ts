import { Controller, Get } from '@nestjs/common';

/**
 * Públicos a propósito: son las probes de Kubernetes y el health check del
 * load balancer. Van sin rate limit, porque limitarlos convierte una ráfaga
 * de tráfico en un reinicio de pods.
 */
@Controller('health')
export class HealthController {
  @Get()
  liveness(): { status: string } {
    return { status: 'ok' };
  }

  @Get('ready')
  readiness(): { status: string } {
    return { status: 'ready' };
  }
}
