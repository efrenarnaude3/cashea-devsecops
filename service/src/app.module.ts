import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';

import { HealthController } from './health/health.controller';
import { NotesController } from './notes/notes.controller';
import { NotesService } from './notes/notes.service';

@Module({
  imports: [
    // ttl en milisegundos (API de @nestjs/throttler v6). El límite se aplica
    // solo donde se declara el guard, no globalmente: un rate limit sobre los
    // health checks rompería las probes.
    ThrottlerModule.forRoot([{ name: 'default', ttl: 60_000, limit: 10 }]),
  ],
  controllers: [HealthController, NotesController],
  providers: [NotesService],
})
export class AppModule {}
