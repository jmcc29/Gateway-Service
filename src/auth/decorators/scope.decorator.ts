import { applyDecorators, SetMetadata, UseGuards } from '@nestjs/common';
import { UserPermissionGuard } from '../guards';

export const SCOPE_KEY = 'scope_key';

export function Scope(scope: string) {
  return applyDecorators(
    SetMetadata(SCOPE_KEY, scope),
  );
}