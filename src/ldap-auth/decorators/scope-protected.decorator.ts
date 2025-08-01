import { applyDecorators, UseGuards } from '@nestjs/common';
import { PermissionProtected } from './permission-protected.decorator';
import { UserPermissionGuard } from '../guards/user-permission.guard';

export function ScopeProtected(scope: string) {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    const controllerName = target.constructor.name; // ej: PersonsController
    const resource = controllerName.replace('Controller', '').toLowerCase(); // persons

    const decorators = applyDecorators(
      UseGuards(UserPermissionGuard),
      PermissionProtected(resource, scope),
    );

    decorators(target, propertyKey, descriptor);
  };
}
