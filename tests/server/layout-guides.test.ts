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
  assert.deepEqual(ids, ['_generic', 'feishu', 'figma', 'qq', 'slack', 'vscode-family', 'wechat']);

  // Validate cross-platform frontmatter metadata across all 7 built-in guides.
  for (const guide of builtIn.list()) {
    assert.equal(guide.platform, 'all');
    assert.equal(guide.source, 'built-in');
    assert.ok(guide.summary.length > 0);
  }

  const figmaGuide = builtIn.findById('figma');
  assert.ok(figmaGuide);
  assert.equal(figmaGuide.name, 'Figma Desktop');
  assert.equal(figmaGuide.platform, 'all');
  assert.equal(figmaGuide.source, 'built-in');
  assert.ok(figmaGuide.summary.length > 0);
  assert.deepEqual(figmaGuide.bundleIds, ['com.figma.Desktop', 'figma.exe']);

  const vscodeGuide = builtIn.findById('vscode-family');
  assert.ok(vscodeGuide);
  assert.equal(vscodeGuide.name, 'VSCode & Electron IDEs');
  assert.equal(vscodeGuide.platform, 'all');
  assert.equal(vscodeGuide.source, 'built-in');
  assert.ok(vscodeGuide.summary.length > 0);
  assert.deepEqual(vscodeGuide.bundleIds, [
    'com.google.antigravity',
    'com.google.antigravity-ide',
    'com.microsoft.VSCode',
    'com.microsoft.VSCodeInsiders',
    'com.todesktop.230313mzl4w4u92',
    'com.exafunction.windsurf',
    'antigravity.exe',
    'antigravityide.exe',
    'code.exe',
    'code-insiders.exe',
    'cursor.exe',
    'windsurf.exe',
  ]);

  assert.deepEqual(builtIn.findById('feishu')?.bundleIds, [
    'com.electron.lark',
    'com.bytedance.feishu',
    'feishu.exe',
    'lark.exe',
  ]);
  assert.deepEqual(builtIn.findById('qq')?.bundleIds, ['com.tencent.qq', 'qq.exe']);
  assert.deepEqual(builtIn.findById('slack')?.bundleIds, [
    'com.tinyspeck.slackmacgap',
    'slack.exe',
    '91750d7e.slack',
  ]);
  assert.deepEqual(builtIn.findById('wechat')?.bundleIds, [
    'com.tencent.xinWeChat',
    'wechat.exe',
    'weixin.exe',
  ]);

  // Case-insensitive bundleId lookup across macOS & Windows multi-bundle guides.
  assert.equal(builtIn.findByApplicationId('COM.TENCENT.QQ')?.id, 'qq');
  assert.equal(builtIn.findByApplicationId('com.electron.lark')?.id, 'feishu');
  assert.equal(builtIn.findByApplicationId('com.bytedance.feishu')?.id, 'feishu');
  assert.equal(builtIn.findByApplicationId('com.figma.Desktop')?.id, 'figma');
  assert.equal(builtIn.findByApplicationId('COM.FIGMA.DESKTOP')?.id, 'figma');
  assert.equal(builtIn.findByApplicationId('com.google.antigravity')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('com.google.antigravity-ide')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('com.microsoft.VSCode')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('com.microsoft.VSCodeInsiders')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('com.todesktop.230313mzl4w4u92')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('com.exafunction.windsurf')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('com.tencent.xinWeChat')?.id, 'wechat');
  assert.equal(builtIn.findByApplicationId('com.tinyspeck.slackmacgap')?.id, 'slack');
  assert.equal(builtIn.findByApplicationId('com.unknown.app'), null);

  // Windows executable and MSIX/UWP package lookups (including case-insensitive variants).
  assert.equal(builtIn.findByApplicationId('feishu.exe')?.id, 'feishu');
  assert.equal(builtIn.findByApplicationId('lark.exe')?.id, 'feishu');
  assert.equal(builtIn.findByApplicationId('figma.exe')?.id, 'figma');
  assert.equal(builtIn.findByApplicationId('Figma.EXE')?.id, 'figma');
  assert.equal(builtIn.findByApplicationId('qq.exe')?.id, 'qq');
  assert.equal(builtIn.findByApplicationId('slack.exe')?.id, 'slack');
  assert.equal(builtIn.findByApplicationId('91750d7e.slack')?.id, 'slack');
  assert.equal(builtIn.findByApplicationId('91750D7E.SLACK')?.id, 'slack');
  assert.equal(builtIn.findByApplicationId('code.exe')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('code-insiders.exe')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('cursor.exe')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('windsurf.exe')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('antigravity.exe')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('antigravityide.exe')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('AntigravityIDE.exe')?.id, 'vscode-family');
  assert.equal(builtIn.findByApplicationId('wechat.exe')?.id, 'wechat');
  assert.equal(builtIn.findByApplicationId('weixin.exe')?.id, 'wechat');
  assert.equal(builtIn.findByApplicationId('notepad.exe'), null);

  // URI resolution enforces strict prefix and identifier validation.
  assert.equal(builtIn.findByUri(`${LAYOUT_GUIDE_URI_PREFIX}qq`)?.id, 'qq');
  assert.equal(builtIn.findByUri(`${LAYOUT_GUIDE_URI_PREFIX}figma`)?.id, 'figma');
  assert.equal(builtIn.findByUri(`${LAYOUT_GUIDE_URI_PREFIX}vscode-family`)?.id, 'vscode-family');
  assert.equal(builtIn.findByUri(`${LAYOUT_GUIDE_URI_PREFIX}../qq`), null);
  assert.equal(builtIn.findByUri('file:///etc/passwd'), null);

  const dir = await mkdtemp(join(tmpdir(), 'chmcp-guides-test-'));
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
    let createdFileSymlink = true;
    try {
      await symlink(secretTarget, join(userDir, 'linked.md'));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (process.platform === 'win32' && (code === 'EPERM' || code === 'EACCES')) {
        createdFileSymlink = false;
      } else {
        throw err;
      }
    }

    const merged = await loadLayoutGuides({ userDir });
    assert.equal(merged.findById('discord')?.source, 'user');
    assert.equal(merged.findByApplicationId('com.hnc.discord')?.id, 'discord');
    assert.equal(merged.findById('qq')?.source, 'user');
    assert.equal(merged.findById('qq')?.name, 'Custom QQ Override');
    if (createdFileSymlink) {
      assert.equal(merged.findById('secret'), null);
      assert.equal(merged.findById('linked'), null);
    }
    assert.equal(merged.findById('broken'), null);
    assert.equal(merged.findById('oversized'), null);

    // 3. Symlinked userDir itself must be ignored.
    const symlinkUserDir = join(dir, 'symlink-guides');
    await symlink(userDir, symlinkUserDir, process.platform === 'win32' ? 'junction' : undefined);
    const ignoredSymlinkDir = await loadLayoutGuides({ userDir: symlinkUserDir });
    assert.equal(ignoredSymlinkDir.findById('discord'), null);
    assert.equal(ignoredSymlinkDir.findById('qq')?.source, 'built-in');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP exposes layout guides via initialize.instructions, history_layout_guide, history_layout pointer, and resources/*', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'chmcp-mcp-guides-'));
  const authStore = await AuthStore.open({ dataDir: dir });
  const mockService = createMockHistoryService(dir);
  await mockService.initializeKey();
  await mockService.start({});

  const qqSnap = makeSampleSurfaceSnapshot('evt_qq', 'snap_qq', 'Project Alpha');
  if (qqSnap.target.kind === 'resolved') {
    qqSnap.target.identity.applicationId = 'com.tencent.qq';
  }
  const figmaSnap = makeSampleSurfaceSnapshot('evt_figma', 'snap_figma', 'Design System');
  if (figmaSnap.target.kind === 'resolved') {
    figmaSnap.target.identity.applicationId = 'com.figma.Desktop';
  }
  const antigravitySnap = makeSampleSurfaceSnapshot('evt_ag', 'snap_ag', 'workspace — index.ts');
  if (antigravitySnap.target.kind === 'resolved') {
    antigravitySnap.target.identity.applicationId = 'com.google.antigravity-ide';
  }
  const vscodeSnap = makeSampleSurfaceSnapshot('evt_vscode', 'snap_vscode', 'repo — app.ts');
  if (vscodeSnap.target.kind === 'resolved') {
    vscodeSnap.target.identity.applicationId = 'com.microsoft.VSCode';
  }
  const unknownSnap = makeSampleSurfaceSnapshot('evt_unknown', 'snap_unknown', 'Editor Window');
  if (unknownSnap.target.kind === 'resolved') {
    unknownSnap.target.identity.applicationId = 'com.unknown.editor';
  }
  mockService.seedObservation(qqSnap);
  mockService.seedObservation(figmaSnap);
  mockService.seedObservation(antigravitySnap);
  mockService.seedObservation(vscodeSnap);
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

    const figmaLayoutRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 201,
        method: 'tools/call',
        params: { name: 'history_layout', arguments: { snapshotId: 'snap_figma' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const figmaLayout = JSON.parse(figmaLayoutRes.result.content[0]!.text) as {
      found: boolean;
      layoutGuide: { available: boolean; id?: string; uri?: string };
    };
    assert.equal(figmaLayout.found, true);
    assert.deepEqual(figmaLayout.layoutGuide, {
      available: true,
      id: 'figma',
      uri: `${LAYOUT_GUIDE_URI_PREFIX}figma`,
    });

    let vscodeLayoutUri = '';
    for (const [reqId, snapshotId] of [
      [202, 'snap_ag'],
      [203, 'snap_vscode'],
    ] as const) {
      const ideLayoutRes = (await (
        await mcpPost(srv.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: reqId,
          method: 'tools/call',
          params: { name: 'history_layout', arguments: { snapshotId } },
        })
      ).json()) as { result: { content: Array<{ text: string }> } };
      const ideLayout = JSON.parse(ideLayoutRes.result.content[0]!.text) as {
        found: boolean;
        layoutGuide: { available: boolean; id?: string; uri?: string };
      };
      assert.equal(ideLayout.found, true);
      assert.deepEqual(ideLayout.layoutGuide, {
        available: true,
        id: 'vscode-family',
        uri: `${LAYOUT_GUIDE_URI_PREFIX}vscode-family`,
      });
      vscodeLayoutUri = ideLayout.layoutGuide.uri!;
    }

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
      ['_generic', 'feishu', 'figma', 'qq', 'slack', 'vscode-family', 'wechat'],
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

    const figmaGuideRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 601,
        method: 'tools/call',
        params: { name: 'history_layout_guide', arguments: { applicationId: 'com.figma.Desktop' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const figmaGuidePayload = JSON.parse(figmaGuideRes.result.content[0]!.text) as {
      matched: boolean;
      guide: { id: string; uri: string; content: string };
      genericGuide?: { id: string };
    };
    assert.equal(figmaGuidePayload.matched, true);
    assert.equal(figmaGuidePayload.guide.id, 'figma');
    assert.equal(figmaGuidePayload.guide.uri, `${LAYOUT_GUIDE_URI_PREFIX}figma`);
    assert.ok(figmaGuidePayload.guide.content.includes('AXLandmarkMain'));
    assert.ok(figmaGuidePayload.guide.content.includes('WebGL/WASM'));
    assert.equal(figmaGuidePayload.genericGuide?.id, GENERIC_LAYOUT_GUIDE_ID);

    for (const [reqId, appId] of [
      [602, 'com.google.antigravity-ide'],
      [603, 'com.microsoft.VSCode'],
    ] as const) {
      const ideGuideRes = (await (
        await mcpPost(srv.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: reqId,
          method: 'tools/call',
          params: { name: 'history_layout_guide', arguments: { applicationId: appId, includeGeneric: false } },
        })
      ).json()) as { result: { content: Array<{ text: string }> } };
      const ideGuidePayload = JSON.parse(ideGuideRes.result.content[0]!.text) as {
        matched: boolean;
        guide: { id: string; uri: string; content: string };
        genericGuide?: unknown;
      };
      assert.equal(ideGuidePayload.matched, true);
      assert.equal(ideGuidePayload.guide.id, 'vscode-family');
      assert.equal(ideGuidePayload.guide.uri, `${LAYOUT_GUIDE_URI_PREFIX}vscode-family`);
      assert.ok(ideGuidePayload.guide.content.includes('AXApplicationStatus'));
      assert.ok(ideGuidePayload.guide.content.includes('Monaco'));
      assert.equal(ideGuidePayload.genericGuide, undefined);
    }

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
    assert.equal(resourcesList.result.resources.length, 7);
    assert.equal(resourcesList.result.resources[0]?.uri, `${LAYOUT_GUIDE_URI_PREFIX}_generic`);
    assert.equal(resourcesList.result.resources[0]?.mimeType, 'text/markdown');
    assert.ok(resourcesList.result.resources.some((r) => r.uri === `${LAYOUT_GUIDE_URI_PREFIX}figma`));
    assert.ok(resourcesList.result.resources.some((r) => r.uri === `${LAYOUT_GUIDE_URI_PREFIX}vscode-family`));

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

    // Resolve resources directly from history_layout pointers for Figma and VSCode-family.
    for (const [reqId, uri, snippet] of [
      [901, figmaLayout.layoutGuide.uri!, 'Figma Design'],
      [902, vscodeLayoutUri, 'workbench.parts.statusbar'],
    ] as const) {
      const readRes = (await (
        await mcpPost(srv.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: reqId,
          method: 'resources/read',
          params: { uri },
        })
      ).json()) as { result: { contents: Array<{ uri: string; mimeType: string; text: string }> } };
      assert.equal(readRes.result.contents.length, 1);
      assert.equal(readRes.result.contents[0]?.uri, uri);
      assert.equal(readRes.result.contents[0]?.mimeType, 'text/markdown');
      assert.ok(readRes.result.contents[0]?.text.includes(snippet));
    }

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

test('MCP resolves Windows executable and MSIX layout guides, case-insensitive IDs, and _generic fallback', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'chmcp-mcp-win-guides-'));
  const authStore = await AuthStore.open({ dataDir: dir });
  const mockService = createMockHistoryService(dir);
  await mockService.initializeKey();
  await mockService.start({});

  const windowsFixtures = [
    ['evt_win_feishu', 'snap_win_feishu', 'feishu.exe', 'feishu'],
    ['evt_win_lark', 'snap_win_lark', 'lark.exe', 'feishu'],
    ['evt_win_figma', 'snap_win_figma', 'figma.exe', 'figma'],
    ['evt_win_qq', 'snap_win_qq', 'qq.exe', 'qq'],
    ['evt_win_slack', 'snap_win_slack', 'slack.exe', 'slack'],
    ['evt_win_slack_msix', 'snap_win_slack_msix', '91750d7e.slack', 'slack'],
    ['evt_win_code', 'snap_win_code', 'code.exe', 'vscode-family'],
    ['evt_win_ag', 'snap_win_ag', 'antigravity.exe', 'vscode-family'],
    ['evt_win_ag_ide', 'snap_win_ag_ide', 'antigravityide.exe', 'vscode-family'],
    ['evt_win_wechat', 'snap_win_wechat', 'wechat.exe', 'wechat'],
    ['evt_win_weixin', 'snap_win_weixin', 'weixin.exe', 'wechat'],
  ] as const;

  for (const [eventId, snapshotId, appId] of windowsFixtures) {
    const snap = makeSampleSurfaceSnapshot(eventId, snapshotId, `${appId} window`);
    if (snap.target.kind === 'resolved') {
      snap.target.identity.applicationId = appId;
    }
    mockService.seedObservation(snap);
  }

  const notepadSnap = makeSampleSurfaceSnapshot('evt_win_notepad', 'snap_win_notepad', 'Untitled - Notepad');
  if (notepadSnap.target.kind === 'resolved') {
    notepadSnap.target.identity.applicationId = 'notepad.exe';
  }
  mockService.seedObservation(notepadSnap);

  const srv = await startHttpServer({
    dataDir: dir,
    port: 0,
    authStore,
    service: mockService,
  });

  try {
    const readLease = await authStore.createLease({ label: 'win-reader', scopes: ['read'], ttlMs: null });

    let reqId = 100;
    for (const [, snapshotId, , expectedGuideId] of windowsFixtures) {
      const layoutRes = (await (
        await mcpPost(srv.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: ++reqId,
          method: 'tools/call',
          params: { name: 'history_layout', arguments: { snapshotId } },
        })
      ).json()) as { result: { content: Array<{ text: string }> } };
      const layoutPayload = JSON.parse(layoutRes.result.content[0]!.text) as {
        found: boolean;
        layoutGuide: { available: boolean; id?: string; uri?: string };
      };
      assert.equal(layoutPayload.found, true);
      assert.deepEqual(layoutPayload.layoutGuide, {
        available: true,
        id: expectedGuideId,
        uri: `${LAYOUT_GUIDE_URI_PREFIX}${expectedGuideId}`,
      });
    }

    // Generic fallback for unmatched Windows app (notepad.exe -> _generic).
    const notepadLayoutRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: ++reqId,
        method: 'tools/call',
        params: { name: 'history_layout', arguments: { snapshotId: 'snap_win_notepad' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const notepadLayout = JSON.parse(notepadLayoutRes.result.content[0]!.text) as {
      found: boolean;
      layoutGuide: { available: boolean; fallbackId?: string; uri?: string };
    };
    assert.equal(notepadLayout.found, true);
    assert.deepEqual(notepadLayout.layoutGuide, {
      available: false,
      fallbackId: GENERIC_LAYOUT_GUIDE_ID,
      uri: `${LAYOUT_GUIDE_URI_PREFIX}${GENERIC_LAYOUT_GUIDE_ID}`,
    });

    // Direct history_layout_guide lookups for Windows IDs (including mixed-case variants).
    for (const [appId, expectedId, expectedSnippet] of [
      ['feishu.exe', 'feishu', 'Shift + Enter to add a new line'],
      ['Figma.EXE', 'figma', 'Ctrl + \\'],
      ['qq.exe', 'qq', 'Two-Column Alignment'],
      ['91750D7E.SLACK', 'slack', '91750d7e.slack'],
      ['code.exe', 'vscode-family', 'AXApplicationStatus'],
      ['antigravity.exe', 'vscode-family', 'workbench.parts.statusbar'],
      ['antigravityide.exe', 'vscode-family', 'workbench.parts.statusbar'],
      ['weixin.exe', 'wechat', 'chat_message_list'],
    ] as const) {
      const guideRes = (await (
        await mcpPost(srv.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: ++reqId,
          method: 'tools/call',
          params: { name: 'history_layout_guide', arguments: { applicationId: appId } },
        })
      ).json()) as { result: { content: Array<{ text: string }> } };
      const payload = JSON.parse(guideRes.result.content[0]!.text) as {
        matched: boolean;
        guide: { id: string; uri: string; platform: string; content: string };
        genericGuide?: { id: string; content: string };
      };
      assert.equal(payload.matched, true);
      assert.equal(payload.guide.id, expectedId);
      assert.equal(payload.guide.uri, `${LAYOUT_GUIDE_URI_PREFIX}${expectedId}`);
      assert.equal(payload.guide.platform, 'all');
      assert.ok(payload.guide.content.includes(expectedSnippet));
      assert.equal(payload.genericGuide?.id, GENERIC_LAYOUT_GUIDE_ID);
      assert.ok(payload.genericGuide?.content.includes('uia.tree'));
    }

    const notepadGuideRes = (await (
      await mcpPost(srv.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: ++reqId,
        method: 'tools/call',
        params: { name: 'history_layout_guide', arguments: { applicationId: 'notepad.exe' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const notepadGuide = JSON.parse(notepadGuideRes.result.content[0]!.text) as {
      matched: boolean;
      guide: null;
      genericGuide: { id: string };
      availableIds: string[];
    };
    assert.equal(notepadGuide.matched, false);
    assert.equal(notepadGuide.guide, null);
    assert.equal(notepadGuide.genericGuide.id, GENERIC_LAYOUT_GUIDE_ID);
    assert.ok(notepadGuide.availableIds.includes('figma'));
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});
