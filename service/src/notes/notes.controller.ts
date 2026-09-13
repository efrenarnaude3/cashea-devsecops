import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';

import { BearerAuthGuard } from '../common/bearer-auth.guard';
import { CreateNoteDto } from './dto/create-note.dto';
import { ListNotesQuery } from './dto/list-notes.query';
import { Note, NotesService } from './notes.service';

@Controller('api/v1/notes')
export class NotesController {
  constructor(private readonly notes: NotesService) {}

  @Get()
  list(@Query() query: ListNotesQuery): Note[] {
    return this.notes.list(query.limit, query.offset);
  }

  // El rate limit va solo acá: es el endpoint que escribe. Aplicarlo global
  // alcanzaría también a /health y rompería las probes bajo carga.
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @UseGuards(BearerAuthGuard, ThrottlerGuard)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  create(@Body() dto: CreateNoteDto): Note {
    return this.notes.create(dto);
  }

  // ParseUUIDPipe rechaza con 400 antes de tocar el store: un ID que no es
  // UUID no llega a ser una consulta.
  @Get(':id')
  findOne(@Param('id', new ParseUUIDPipe({ version: '4' })) id: string): Note {
    return this.notes.findOne(id);
  }
}
