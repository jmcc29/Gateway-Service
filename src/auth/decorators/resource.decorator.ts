import { SetMetadata } from '@nestjs/common';
export const RESOURCE_KEY = 'resource_key';

export const Resource = (resource: string) => SetMetadata(RESOURCE_KEY, resource);
