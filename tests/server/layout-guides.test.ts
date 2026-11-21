import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AuthStore } from '../../src/server/auth-store.ts';
import { startHttpServer } from '../../src/server/http-server.ts';
import {
  GENERIC_LAYOUT_GUIDE_ID,
  LAYOUT_GUIDE_URI_PREFIX,
  loadLayoutGuides,
  MAX_LAYOUT_GUIDE_FILE_BYTES,
} from '../../src/server/layout-guides.ts';
import { MCP_SERVER_INSTRUCTIONS } from '../../src/server/mcp-handler.ts';
import { createMockHistoryService, makeSampleSurfaceSnapshot } from './mock-service.ts';

async function mcpPost(mcpUrl: string, token: string, body: unknown): Promise<Response> {
  return await fetch(mcpUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
}

test('loadLayoutGuides parses built-in guides, supports user overrides, and rejects symlinks or oversized files', async () => {
  const builtIn = await loadLayoutGuides();
  const ids = builtIn.list().map((g) => g.id);
  assert.equal(ids[0], GENERIC_LAYOUT_GUIDE_ID);
  assert.deepEqual(ids, ['_generic', 'feishu', 'qq', 'slack', 'wechat']);

  // Case-insensitive bundleId lookup across multi-bundle guides.
  assert.equal(builtIn.findByApplicationId('COM.TENCENT.QQ')?.id, 'qq');
  assert.equal(builtIn.findByApplicationId('com.electron.lark')?.id, 'feishu');
  assert.equal(builtIn.findByApplicationId('com.bytedance.feishu')?.id, 'feishu');
  assert.equal(builtIn.findByApplicationId('com.tencent.xinWeChat')?.id, 'wechat');
  assert.equal(builtIn.findByApplicationId('com.tinyspeck.slackmacgap')?.id, 'slack');
  assert.equal(builtIn.findByApplicationId('com.unknown.app'), null);

  // URI resolution enforces strict prefix and identifier validation.
  assert.equal(builtIn.findByUri(`${LAYOUT_GUIDE_URI_PREFIX}qq`)?.id, 'qq');
  assert.equal(builtIn.findByUri(`${LAYOUT_GUIDE_URI_PREFIX}../qq`), null);
  assert.equal(builtIn.findByUri('file:///etc/passwd'), null);

  const dir = await mkdtemp(join(tmpdir(), 'camcp-guides-test-'));
  const userDir = join(dir, 'layout-guides');
  await mkdir(userDir, { recursive: true });
  const secretTarget = join(dir, 'secret.md');
  await writeFile(
    secretTarget,
    '---\nid: secret\nname: Secret\nbundleIds:\n  - com.evil.app\nsummary: must not load via symlink\n---\nSecret body\n',
  );

  try {
    // 1. Valid custom guide and override of built-in qq.md.
    await writeFile(
      join(userDir, 'discord.md'),
      [
        '---',
        'id: discord',
        'name: Discord',
        'bundleIds:',
        '  - com.hnc.Discord',
        'platform: darwin',
        'summary: Single-column Discord channel guide.',
        '---',
        '',
        '## Active Channel',
        'Read top channel heading.',
      ].join('\n'),
    );
    await writeFile(
      join(userDir, 'qq.md'),
      [
        '---',
        'id: qq',
        'name: Custom QQ Override',
        'bundleIds:',
        '  - com.tencent.qq',
        'platform: darwin',
        'summary: User override for QQ.',
        '---',
        '',
        'Custom QQ instructions.',
      ].join('\n'),
    );

    // 2. Malformed frontmatter, invalid id, oversized file, and symlink must all be safely ignored.
    await writeFile(join(userDir, 'broken.md'), '# Missing frontmatter\nJust body.');
    await writeFile(
      join(userDir, 'bad-id.md'),
      '---\nid: ../escape\nname: Bad\nsummary: invalid id\n---\nNope',
    );
    await writeFile(
      join(userDir, 'oversized.md'),
      `---\nid: oversized\nname: Big\nsummary: Too large\n---\n${'x'.repeat(MAX_LAYOUT_GUIDE_FILE_BYTES + 128)}`,
    );
    await symlink(secretTarget, join(userDir, 'linked.md'));

    const merged = await loadLayoutGuides({ userDir });
    assert.equal(merged.findById('discord')?.source, 'user');
    assert.equal(merged.findByApplicationId('com.hnc.discord')?.id, 'discord');
    assert.equal(merged.findById('qq')?.source, 'user');
    assert.equal(merged.findById('qq')?.name, 'Custom QQ Override');
    assert.equal(merged.findById('secret'), null);
    assert.equal(merged.findById('linked'), null);
    assert.equal(merged.findById('broken'), null);
    assert.equal(merged.findById('oversized'), null);

    // 3. Symlinked userDir itself must be ignored.
    const symlinkUserDir = join(dir, 'symlink-guides');
    await symlink(userDir, symlinkUserDir);
    const ignoredSymlinkDir = await loadLayoutGuides({ userDir: symlinkUserDir });
    assert.equal(ignoredSymlinkDir.findById('discord'), null);
    assert.equal(ignoredSymlinkDir.findById('qq')?.source, 'built-in');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP exposes layout guides via initialize.instructions, history_layout_guide, history_layout pointer, and resources/*', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'camcp-mcp-guides-'));
  const authStore = await AuthStore.open({ dataDir: dir });
  const mockService = createMockHistoryService(dir);
  await mockService.initializeKey();
  await mockService.start({});

  const qqSnap = makeSampleSurfaceSnapshot('evt_qq', 'snap_qq', 'Project Alpha');
  if (qqSnap.target.kind === 'resolved') {
    qqSnap.target.identity.applicationId = 'com.tencent.qq';
  }
  const unknownSnap = makeSampleSurfaceSnapshot('evt_unknown', 'snap_unknown', 'Editor Window');
  mockService.seedObservation(qqSnap);
  mockService.seedObservation(unknownSnap);

  const srv = await startHttpServer({
    dataDir: dir,
    port: 0,
    authStore,
    service: mockService,
  });

  try {
    const readLease = await authStore.createLease({ label: 'reader', scopes: ['read'], ttlMs: null });
    const pauseOnlyLease = await authStore.createLease({ label: 'pauser', scopes: ['pause'], ttlMs: null });

    // 1. initialize returns capabilities.resources and instructions.
    const initJson = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } },
      })
    ).json()) as {
      result: { capabilities: Record<string, unknown>; instructions: string };
    };
    assert.deepEqual(initJson.result.capabilities, { tools: {}, resources: {} });
    assert.equal(initJson.result.instructions, MCP_SERVER_INSTRUCTIONS);

    // 2. history_layout attaches lightweight layoutGuide pointer (matched vs fallback).
    const qqLayoutRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'history_layout', arguments: { snapshotId: 'snap_qq' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const qqLayout = JSON.parse(qqLayoutRes.result.content[0]!.text) as {
      found: boolean;
      layoutGuide: { available: boolean; id?: string; uri?: string };
    };
    assert.equal(qqLayout.found, true);
    assert.deepEqual(qqLayout.layoutGuide, {
      available: true,
      id: 'qq',
      uri: `${LAYOUT_GUIDE_URI_PREFIX}qq`,
    });

    const unknownLayoutRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'history_layout', arguments: { snapshotId: 'snap_unknown' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const unknownLayout = JSON.parse(unknownLayoutRes.result.content[0]!.text) as {
      found: boolean;
      layoutGuide: { available: boolean; fallbackId?: string; uri?: string };
    };
    assert.equal(unknownLayout.found, true);
    assert.deepEqual(unknownLayout.layoutGuide, {
      available: false,
      fallbackId: GENERIC_LAYOUT_GUIDE_ID,
      uri: `${LAYOUT_GUIDE_URI_PREFIX}${GENERIC_LAYOUT_GUIDE_ID}`,
    });

    // 3. history_layout_guide index, matched app lookup, includeGeneric:false, and fallback.
    const indexRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: { name: 'history_layout_guide', arguments: {} },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const indexPayload = JSON.parse(indexRes.result.content[0]!.text) as {
      guides: Array<{ id: string; uri: string }>;
    };
    assert.deepEqual(
      indexPayload.guides.map((g) => g.id),
      ['_generic', 'feishu', 'qq', 'slack', 'wechat'],
    );

    const qqGuideRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: { name: 'history_layout_guide', arguments: { applicationId: 'com.tencent.qq' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const qqGuidePayload = JSON.parse(qqGuideRes.result.content[0]!.text) as {
      matched: boolean;
      guide: { id: string; content: string };
      genericGuide?: { id: string; content: string };
    };
    assert.equal(qqGuidePayload.matched, true);
    assert.equal(qqGuidePayload.guide.id, 'qq');
    assert.ok(qqGuidePayload.guide.content.includes('Two-Column Alignment'));
    assert.equal(qqGuidePayload.genericGuide?.id, GENERIC_LAYOUT_GUIDE_ID);

    const feishuNoGenericRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 6,
        method: 'tools/call',
        params: {
          name: 'history_layout_guide',
          arguments: { applicationId: 'com.electron.lark', includeGeneric: false },
        },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const feishuPayload = JSON.parse(feishuNoGenericRes.result.content[0]!.text) as {
      matched: boolean;
      guide: { id: string; content: string };
      genericGuide?: unknown;
    };
    assert.equal(feishuPayload.matched, true);
    assert.equal(feishuPayload.guide.id, 'feishu');
    assert.ok(feishuPayload.guide.content.includes('发送给'));
    assert.equal(feishuPayload.genericGuide, undefined);

    const missingGuideRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: { name: 'history_layout_guide', arguments: { applicationId: 'com.unknown.editor' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const missingPayload = JSON.parse(missingGuideRes.result.content[0]!.text) as {
      matched: boolean;
      guide: null;
      genericGuide: { id: string };
      availableIds: string[];
    };
    assert.equal(missingPayload.matched, false);
    assert.equal(missingPayload.guide, null);
    assert.equal(missingPayload.genericGuide.id, GENERIC_LAYOUT_GUIDE_ID);
    assert.ok(missingPayload.availableIds.includes('qq'));

    // 4. resources/list and resources/read.
    const resourcesList = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 8,
        method: 'resources/list',
      })
    ).json()) as { result: { resources: Array<{ uri: string; mimeType: string; name: string }> } };
    assert.equal(resourcesList.result.resources.length, 5);
    assert.equal(resourcesList.result.resources[0]?.uri, `${LAYOUT_GUIDE_URI_PREFIX}_generic`);
    assert.equal(resourcesList.result.resources[0]?.mimeType, 'text/markdown');

    const resourceRead = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 9,
        method: 'resources/read',
        params: { uri: `${LAYOUT_GUIDE_URI_PREFIX}wechat` },
      })
    ).json()) as { result: { contents: Array<{ uri: string; mimeType: string; text: string }> } };
    assert.equal(resourceRead.result.contents.length, 1);
    assert.equal(resourceRead.result.contents[0]?.uri, `${LAYOUT_GUIDE_URI_PREFIX}wechat`);
    assert.equal(resourceRead.result.contents[0]?.mimeType, 'text/markdown');
    assert.ok(resourceRead.result.contents[0]?.text.includes('引用'));

    // Unknown URI returns -32002; invalid params returns -32602.
    const unknownUri = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 10,
        method: 'resources/read',
        params: { uri: `${LAYOUT_GUIDE_URI_PREFIX}nonexistent` },
      })
    ).json()) as { error?: { code: number } };
    assert.equal(unknownUri.error?.code, -32002);

    const missingUri = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 11,
        method: 'resources/read',
        params: {},
      })
    ).json()) as { error?: { code: number } };
    assert.equal(missingUri.error?.code, -32602);

    // 5. Scope enforcement: pause-only lease cannot read resources or call history_layout_guide.
    for (const req of [
      { jsonrpc: '2.0', id: 20, method: 'resources/list' },
      {
        jsonrpc: '2.0',
        id: 21,
        method: 'resources/read',
        params: { uri: `${LAYOUT_GUIDE_URI_PREFIX}qq` },
      },
      {
        jsonrpc: '2.0',
        id: 22,
        method: 'tools/call',
        params: { name: 'history_layout_guide', arguments: {} },
      },
    ]) {
      const denied = (await (await mcpPost(srv.mcpUrl, pauseOnlyLease.token, req)).json()) as {
        error?: { code: number };
      };
      assert.equal(denied.error?.code, -32003);
    }

    // 6. Hot-drop user guide inside dataDir/layout-guides takes effect immediately without restart.
    const liveUserDir = join(dir, 'layout-guides');
    await mkdir(liveUserDir, { recursive: true });
    await writeFile(
      join(liveUserDir, 'telegram.md'),
      '---\nid: telegram\nname: Telegram\nbundleIds:\n  - ru.keepcoder.Telegram\nplatform: darwin\nsummary: Telegram layout notes.\n---\nTop bar shows chat title.\n',
    );
    const liveResources = (await (
      await mcpPost(srv.mcpUrl, readLease.token, { jsonrpc: '2.0', id: 30, method: 'resources/list' })
    ).json()) as { result: { resources: Array<{ uri: string }> } };
    assert.ok(liveResources.result.resources.some((r) => r.uri === `${LAYOUT_GUIDE_URI_PREFIX}telegram`));
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});
