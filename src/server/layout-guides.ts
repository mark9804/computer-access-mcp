import { constants } from 'node:fs';
import { lstat, open, readdir } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const LAYOUT_GUIDE_URI_PREFIX = 'computer-history://layout-guides/';
export const GENERIC_LAYOUT_GUIDE_ID = '_generic';
export const MAX_LAYOUT_GUIDE_FILE_BYTES = 16 * 1024;
export const MAX_LAYOUT_GUIDE_FILES = 64;

const VALID_GUIDE_ID_RE = /^[a-z0-9_-]{1,48}$/;
const DEFAULT_PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const DEFAULT_BUILT_IN_LAYOUT_GUIDES_DIR = join(DEFAULT_PKG_ROOT, 'layout-guides');

export type LayoutGuideSource = 'built-in' | 'user';

export interface LayoutGuideSummary {
  readonly id: string;
  readonly uri: string;
  readonly name: string;
  readonly bundleIds: readonly string[];
  readonly platform: string;
  readonly summary: string;
  readonly source: LayoutGuideSource;
}

export interface LayoutGuide extends LayoutGuideSummary {
  readonly content: string;
  readonly rawMarkdown: string;
}

export interface LayoutGuideStoreOptions {
  builtInDir?: string;
  userDir?: string;
}

export interface LayoutGuideCollection {
  readonly guides: readonly LayoutGuide[];
  list(): readonly LayoutGuide[];
  generic(): LayoutGuide | null;
  findById(id: string): LayoutGuide | null;
  findByApplicationId(applicationId: string): LayoutGuide | null;
  findByUri(uri: string): LayoutGuide | null;
}

interface ParsedFrontmatter {
  scalars: Record<string, string>;
  lists: Record<string, string[]>;
  body: string;
}

function unquoteScalar(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function parseFrontmatter(rawMarkdown: string): ParsedFrontmatter | null {
  const normalized = rawMarkdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  if (lines[0]?.trim() !== '---') {
    return null;
  }

  let endIndex = -1;
  for (let i = 1; i < lines.length; i += 1) {
    if (lines[i]?.trim() === '---') {
      endIndex = i;
      break;
    }
  }
  if (endIndex === -1) {
    return null;
  }

  const scalars: Record<string, string> = {};
  const lists: Record<string, string[]> = {};
  let activeListKey: string | null = null;

  for (let i = 1; i < endIndex; i += 1) {
    const line = lines[i] ?? '';
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }

    if (activeListKey !== null && /^\s+-\s+/.test(line)) {
      const item = unquoteScalar(trimmed.slice(1));
      if (item.length > 0) {
        lists[activeListKey]!.push(item);
      }
      continue;
    }

    activeListKey = null;
    const colon = line.indexOf(':');
    if (colon <= 0) {
      return null;
    }

    const key = line.slice(0, colon).trim();
    const rest = line.slice(colon + 1).trim();
    if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(key)) {
      return null;
    }

    if (rest === '') {
      lists[key] = [];
      activeListKey = key;
    } else if (rest === '[]') {
      lists[key] = [];
    } else if (rest.startsWith('[') && rest.endsWith(']')) {
      const inner = rest.slice(1, -1).trim();
      lists[key] =
        inner.length === 0
          ? []
          : inner
              .split(',')
              .map((part) => unquoteScalar(part))
              .filter((part) => part.length > 0);
    } else {
      scalars[key] = unquoteScalar(rest);
    }
  }

  const body = lines
    .slice(endIndex + 1)
    .join('\n')
    .trim();
  if (body.length === 0) {
    return null;
  }

  return { scalars, lists, body };
}

function parseGuideDocument(rawText: string, filename: string, source: LayoutGuideSource): LayoutGuide | null {
  const normalized = rawText.replace(/\r\n/g, '\n');
  const parsed = parseFrontmatter(normalized);
  if (!parsed) {
    return null;
  }

  const stem = basename(filename, '.md').toLowerCase();
  const id = (parsed.scalars.id ?? stem).trim().toLowerCase();
  if (!VALID_GUIDE_ID_RE.test(id)) {
    return null;
  }

  const name = parsed.scalars.name?.trim() ?? '';
  const summary = parsed.scalars.summary?.trim() ?? '';
  const platform = (parsed.scalars.platform?.trim() || 'all').toLowerCase();
  if (name.length === 0 || summary.length === 0) {
    return null;
  }

  const rawBundleIds = parsed.lists.bundleIds ?? [];
  const seen = new Set<string>();
  const bundleIds: string[] = [];
  for (const rawId of rawBundleIds) {
    const trimmed = rawId.trim();
    if (trimmed.length === 0) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    bundleIds.push(trimmed);
  }

  return Object.freeze({
    id,
    uri: `${LAYOUT_GUIDE_URI_PREFIX}${id}`,
    name,
    bundleIds: Object.freeze(bundleIds),
    platform,
    summary,
    source,
    content: parsed.body,
    rawMarkdown: normalized.trimEnd(),
  });
}

async function readGuideDirectory(dirPath: string, source: LayoutGuideSource): Promise<LayoutGuide[]> {
  let dirStat;
  try {
    dirStat = await lstat(dirPath);
  } catch {
    return [];
  }
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) {
    return [];
  }

  let entries: string[];
  try {
    entries = (await readdir(dirPath))
      .filter((entry) => entry.endsWith('.md') && !entry.startsWith('.'))
      .sort((a, b) => a.localeCompare(b))
      .slice(0, MAX_LAYOUT_GUIDE_FILES);
  } catch {
    return [];
  }

  const openFlags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const results: LayoutGuide[] = [];

  for (const entry of entries) {
    const fullPath = join(dirPath, entry);
    let fh: Awaited<ReturnType<typeof open>> | null = null;
    try {
      // Check lstat before opening so symlink rejection holds uniformly on non-POSIX platforms too.
      const preStat = await lstat(fullPath);
      if (!preStat.isFile() || preStat.isSymbolicLink() || preStat.size === 0 || preStat.size > MAX_LAYOUT_GUIDE_FILE_BYTES) {
        continue;
      }
      fh = await open(fullPath, openFlags);
      const fdStat = await fh.stat();
      if (!fdStat.isFile() || fdStat.size === 0 || fdStat.size > MAX_LAYOUT_GUIDE_FILE_BYTES) {
        continue;
      }
      const buf = await fh.readFile();
      if (buf.byteLength === 0 || buf.byteLength > MAX_LAYOUT_GUIDE_FILE_BYTES) {
        continue;
      }
      const guide = parseGuideDocument(buf.toString('utf8'), entry, source);
      if (guide) {
        results.push(guide);
      }
    } catch {
      // Ignore unreadable, symlinked, or malformed individual guide files without failing the server.
    } finally {
      if (fh) {
        await fh.close().catch(() => {});
      }
    }
  }

  return results;
}

export function toLayoutGuideSummary(guide: LayoutGuide): LayoutGuideSummary {
  return {
    id: guide.id,
    uri: guide.uri,
    name: guide.name,
    bundleIds: [...guide.bundleIds],
    platform: guide.platform,
    summary: guide.summary,
    source: guide.source,
  };
}

export async function loadLayoutGuides(options: LayoutGuideStoreOptions = {}): Promise<LayoutGuideCollection> {
  const builtInDir = resolve(options.builtInDir ?? DEFAULT_BUILT_IN_LAYOUT_GUIDES_DIR);
  const byId = new Map<string, LayoutGuide>();

  for (const guide of await readGuideDirectory(builtInDir, 'built-in')) {
    byId.set(guide.id, guide);
  }

  if (options.userDir) {
    const userDir = resolve(options.userDir);
    for (const guide of await readGuideDirectory(userDir, 'user')) {
      byId.set(guide.id, guide);
    }
  }

  const ordered = [...byId.values()].sort((a, b) => {
    if (a.id === GENERIC_LAYOUT_GUIDE_ID && b.id !== GENERIC_LAYOUT_GUIDE_ID) return -1;
    if (b.id === GENERIC_LAYOUT_GUIDE_ID && a.id !== GENERIC_LAYOUT_GUIDE_ID) return 1;
    return a.id.localeCompare(b.id);
  });

  // Map bundleId -> guide, letting user guides take precedence over built-in guides on collision.
  const byBundleId = new Map<string, LayoutGuide>();
  for (const guide of ordered) {
    if (guide.source === 'built-in') {
      for (const bundleId of guide.bundleIds) {
        byBundleId.set(bundleId.toLowerCase(), guide);
      }
    }
  }
  for (const guide of ordered) {
    if (guide.source === 'user') {
      for (const bundleId of guide.bundleIds) {
        byBundleId.set(bundleId.toLowerCase(), guide);
      }
    }
  }

  const frozenGuides = Object.freeze(ordered);

  return {
    guides: frozenGuides,
    list: () => frozenGuides,
    generic: () => byId.get(GENERIC_LAYOUT_GUIDE_ID) ?? null,
    findById: (id: string) => {
      const normalized = id.trim().toLowerCase();
      if (!VALID_GUIDE_ID_RE.test(normalized)) return null;
      return byId.get(normalized) ?? null;
    },
    findByApplicationId: (applicationId: string) => {
      const normalized = applicationId.trim().toLowerCase();
      if (normalized.length === 0) return null;
      return byBundleId.get(normalized) ?? null;
    },
    findByUri: (uri: string) => {
      if (!uri.startsWith(LAYOUT_GUIDE_URI_PREFIX)) return null;
      const id = uri.slice(LAYOUT_GUIDE_URI_PREFIX.length);
      if (!VALID_GUIDE_ID_RE.test(id)) return null;
      return byId.get(id) ?? null;
    },
  };
}
