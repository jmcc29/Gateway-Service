import { NotFoundException, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from './auth.guard';

describe('AuthGuard (legacy PVT compatibility)', () => {
  const nats = { firstValue: jest.fn() };
  const reflector = { getAllAndOverride: jest.fn().mockReturnValue(false) };
  const guard = new AuthGuard(nats as never, reflector as never);

  const context = (headers: Record<string, string>) =>
    ({
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: () => ({ getRequest: () => ({ headers }) }),
    }) as never;

  beforeEach(() => {
    jest.clearAllMocks();
    reflector.getAllAndOverride.mockReturnValue(false);
  });

  it('validates the PVT x-api-key through Auth-Service', async () => {
    nats.firstValue.mockResolvedValue(true);

    await expect(guard.canActivate(context({ 'x-api-key': 'key' }))).resolves.toBe(true);
    expect(nats.firstValue).toHaveBeenCalledWith('auth.verify.apiKey', 'key');
  });

  it('rejects requests without legacy credentials', async () => {
    await expect(guard.canActivate(context({}))).rejects.toBeInstanceOf(NotFoundException);
  });

  it('maps failed legacy validation to unauthorized', async () => {
    nats.firstValue.mockRejectedValue(new Error('invalid'));

    await expect(guard.canActivate(context({ 'x-api-key': 'bad' }))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
