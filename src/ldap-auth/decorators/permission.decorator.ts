import { SetMetadata } from '@nestjs/common';
export const META_PERMISSION = 'permission';

export interface PermissionMetadata {
  resource: string;
  scope: string;
}
export const PermissionProtected = (resource: string, scope: string) =>
  SetMetadata(META_PERMISSION, { resource, scope });
