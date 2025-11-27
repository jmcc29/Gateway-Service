// src/auth/decorators/audience.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const AUDIENCE_KEY = 'audience_key';

export const Audience = (audience: string) =>
  SetMetadata(AUDIENCE_KEY, audience);
