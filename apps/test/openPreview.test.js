import { EventEmitter } from 'node:events';

import { describe, expect, it, vi } from 'vitest';

import {
  OpenPreviewError,
  checkPreviewOnline,
  currentBranch,
  launchPreviewBrowser,
  parseOpenPreviewArguments,
  previewHostResolverRules,
  resolvePublicIpv4,
  waitForDevtoolsUrl,
} from '../scripts/open-preview.mjs';

describe('open preview', () => {
  it('uses the default profile unless one is selected', () => {
    expect(parseOpenPreviewArguments([])).toEqual({ profile: 'default' });
    expect(parseOpenPreviewArguments(['--profile', 'second-device'])).toEqual({
      profile: 'second-device',
    });
  });

  it('rejects unsafe profile names', () => {
    expect(() => parseOpenPreviewArguments(['--profile', '../outside'])).toThrow(OpenPreviewError);
  });

  it('requires a non-main branch', () => {
    expect(currentBranch(() => 'feat/example-preview\n')).toBe('feat/example-preview');
    expect(() => currentBranch(() => 'main\n')).toThrowError(/does not have a branch preview/);
    expect(() => currentBranch(() => '')).toThrowError(/detached HEAD/);
  });

  it('resolves the preview edge through encrypted DNS', async () => {
    const fetchImplementation = vi.fn().mockResolvedValue({
      json: async () => ({
        Answer: [
          { data: 'preview.cloudfront.net.', type: 5 },
          { data: '203.0.113.8', type: 1 },
        ],
      }),
      ok: true,
    });

    await expect(resolvePublicIpv4('branch-preview.app.example.invalid', fetchImplementation))
      .resolves.toBe('203.0.113.8');
    expect(fetchImplementation).toHaveBeenCalledWith(
      expect.stringContaining('dns.google'),
      { headers: { accept: 'application/dns-json' } },
    );
  });

  it('maps both preview hosts to the verified edge', () => {
    expect(previewHostResolverRules({
      apiUrl: 'https://branch-preview.api.example.invalid',
      appUrl: 'https://branch-preview.app.example.invalid',
    }, '203.0.113.8')).toBe(
      'MAP branch-preview.app.example.invalid 203.0.113.8, '
      + 'MAP branch-preview.api.example.invalid 203.0.113.8',
    );
  });

  it('checks preview availability through the resolved edge', async () => {
    let requestOptions;
    const requestImplementation = vi.fn((options, callback) => {
      requestOptions = options;
      const response = new EventEmitter();
      response.statusCode = 200;
      response.resume = vi.fn();
      queueMicrotask(() => callback(response));
      const request = new EventEmitter();
      request.end = vi.fn();
      request.destroy = vi.fn();
      return request;
    });

    await expect(checkPreviewOnline(
      'https://branch-preview.app.example.invalid',
      '203.0.113.8',
      requestImplementation,
    )).resolves.toBe(200);
    expect(requestOptions.hostname).toBe('branch-preview.app.example.invalid');
    expect(requestOptions.servername).toBe('branch-preview.app.example.invalid');
    const lookup = vi.fn();
    requestOptions.lookup('ignored', {}, lookup);
    expect(lookup).toHaveBeenCalledWith(null, '203.0.113.8', 4);
    requestOptions.lookup('ignored', { all: true }, lookup);
    expect(lookup).toHaveBeenLastCalledWith(null, [{ address: '203.0.113.8', family: 4 }]);
  });

  it('finds the exact preview page in the local DevTools target list', async () => {
    const fetchImplementation = vi.fn().mockResolvedValue({
      json: async () => [
        {
          devtoolsFrontendUrl: 'https://chrome-devtools-frontend.appspot.com/inspector.html?worker',
          type: 'worker',
          url: 'https://branch-preview.app.example.invalid/worker.js',
        },
        {
          devtoolsFrontendUrl: 'https://chrome-devtools-frontend.appspot.com/inspector.html?page',
          type: 'page',
          url: 'https://branch-preview.app.example.invalid/',
        },
      ],
      ok: true,
    });

    await expect(waitForDevtoolsUrl(
      9223,
      'https://branch-preview.app.example.invalid',
      fetchImplementation,
    )).resolves.toContain('inspector.html?page');
  });

  it('opens the preview directly as an interactive DevTools screencast', async () => {
    const context = {
      close: vi.fn(),
      newPage: vi.fn(),
      once: vi.fn(),
      pages: () => [{ goto: vi.fn().mockResolvedValue(undefined) }],
    };
    const browser = {
      launchPersistentContext: vi.fn().mockResolvedValue(context),
    };
    const openUrl = vi.fn();

    await expect(launchPreviewBrowser({
      appUrl: 'https://branch-preview.app.example.invalid',
      browser,
      findPort: async () => 9223,
      openUrl,
      profilePath: 'preview-profile',
      resolverRules: 'MAP preview.example 203.0.113.8',
      waitForClose: async () => undefined,
      waitForDevtools: async () => 'https://chrome-devtools-frontend.appspot.com/inspector',
    })).resolves.toBe('devtools');
    expect(browser.launchPersistentContext).toHaveBeenCalledOnce();
    expect(browser.launchPersistentContext).toHaveBeenCalledWith(
      'preview-profile',
      expect.objectContaining({
        args: expect.arrayContaining(['--remote-debugging-port=9223']),
        headless: true,
      }),
    );
    expect(openUrl).toHaveBeenCalledWith(
      'https://chrome-devtools-frontend.appspot.com/inspector',
    );
  });
});
