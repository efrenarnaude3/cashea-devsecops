import { randomUUID } from 'node:crypto';

import { Injectable, NotFoundException } from '@nestjs/common';

import { CreateNoteDto } from './dto/create-note.dto';

export interface Note {
  id: string;
  title: string;
  body: string;
}

/**
 * Store en memoria: el objeto de este repo es el gate del pipeline, no la
 * persistencia. Un servicio real usa Cloud SQL con queries parametrizadas.
 *
 * Los IDs son UUID y no enteros secuenciales. Con IDs secuenciales, un IDOR
 * es contar hasta el siguiente número.
 */
@Injectable()
export class NotesService {
  private readonly notes = new Map<string, Note>();

  create(dto: CreateNoteDto): Note {
    const note: Note = { id: randomUUID(), title: dto.title, body: dto.body };
    this.notes.set(note.id, note);
    return note;
  }

  findOne(id: string): Note {
    const note = this.notes.get(id);
    if (!note) {
      throw new NotFoundException('Not found');
    }
    return note;
  }

  list(limit: number, offset: number): Note[] {
    return [...this.notes.values()].slice(offset, offset + limit);
  }

  /** Solo para los tests: cada caso arranca con el store vacío. */
  clear(): void {
    this.notes.clear();
  }
}
