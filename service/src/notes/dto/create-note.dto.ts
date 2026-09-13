import { IsString, Length } from 'class-validator';

/**
 * Con `whitelist` + `forbidNonWhitelisted` en el ValidationPipe global, un
 * campo que no esté acá declarado no se ignora: devuelve 400. Es lo que corta
 * el mass assignment, que es cómo un `isAdmin: true` termina persistido.
 */
export class CreateNoteDto {
  @IsString()
  @Length(1, 120)
  title!: string;

  @IsString()
  @Length(0, 2000)
  body!: string;
}
