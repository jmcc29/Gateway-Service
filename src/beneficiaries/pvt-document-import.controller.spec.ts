import { PvtDocumentImportController } from './pvt-document-import.controller';

describe('PvtDocumentImportController', () => {
  const nats = { send: jest.fn() };
  const controller = new PvtDocumentImportController(nats as never);

  beforeEach(() => jest.clearAllMocks());

  it('preserves the legacy analysis payload', () => {
    const payload = { path: '/ignored/by-service', user: 'operator', pass: 'secret' };
    nats.send.mockReturnValue('analysis');

    expect(controller.documentsAnalysis(payload)).toBe('analysis');
    expect(nats.send).toHaveBeenCalledWith('affiliate.documentsAnalysis', payload);
  });

  it('forwards the complete legacy import plan', () => {
    const payload = { dataValidRealExist: [], dataValidRealNotExist: [], user: {} };
    nats.send.mockReturnValue('import');

    expect(controller.documentsImports(payload)).toBe('import');
    expect(nats.send).toHaveBeenCalledWith('affiliate.documentsImports', payload);
  });
});
