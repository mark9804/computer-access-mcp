import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';

export const DEFAULT_STDIO_MCP_URL = 'http://127.0.0.1:43180/mcp';

type JsonRpcId = string | number | null;

export interface StdioProxyOptions {
  url?: string;
  token?: string;
  env?: NodeJS.ProcessEnv;
  input?: Readable;
  output?: Writable;
  errorOutput?: Writable;
  fetchImpl?: typeof fetch;
}

function validateLoopbackMcpUrl(rawUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid MCP URL: ${rawUrl}`);
  }
  if (parsed.protocol !== 'http:') {
    throw new Error(`MCP stdio proxy requires an http:// loopback URL, got: ${parsed.protocol}`);
  }
  const host = parsed.hostname.toLowerCase();
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '[::1]') {
    throw new Error(`Refusing to forward bearer token to non-loopback host: ${parsed.hostname}`);
  }
  return parsed.toString();
}

function writeLine(output: Writable, payload: unknown): Promise<void> {
  const line = `${JSON.stringify(payload)}\n`;
  return new Promise<void>((resolveWrite, rejectWrite) => {
    const ok = output.write(line, 'utf8', (err) => {
      if (err) rejectWrite(err);
      else resolveWrite();
    });
    if (!ok) {
      output.once('drain', () => {});
    }
  });
}

function extractMessageId(item: unknown): { expectsResponse: boolean; id: JsonRpcId } {
  if (item === null || typeof item !== 'object' || Array.isArray(item)) {
    return { expectsResponse: true, id: null };
  }
  const rec = item as Record<string, unknown>;
  if (rec.jsonrpc !== '2.0' || typeof rec.method !== 'string' || rec.method.length === 0) {
    const rawId = rec.id;
    const id: JsonRpcId =
      typeof rawId === 'string' || typeof rawId === 'number' || rawId === null ? rawId : null;
    return { expectsResponse: true, id };
  }
  if (!('id' in rec) || rec.id === undefined) {
    return { expectsResponse: false, id: null };
  }
  const rawId = rec.id;
  const id: JsonRpcId =
    typeof rawId === 'string' || typeof rawId === 'number' || rawId === null ? rawId : null;
  return { expectsResponse: true, id };
}

function buildSynthesizedError(
  parsedInput: unknown,
  code: number,
  message: string,
  data?: unknown,
): unknown | null {
  const makeErr = (id: JsonRpcId) => ({
    jsonrpc: '2.0' as const,
    id,
    error: data !== undefined ? { code, message, data } : { code, message },
  });

  if (Array.isArray(parsedInput)) {
    if (parsedInput.length === 0) {
      return makeErr(null);
    }
    const items = parsedInput
      .map((entry) => extractMessageId(entry))
      .filter((meta) => meta.expectsResponse)
      .map((meta) => makeErr(meta.id));
    return items.length > 0 ? items : null;
  }

  const meta = extractMessageId(parsedInput);
  if (!meta.expectsResponse) {
    return null;
  }
  return makeErr(meta.id);
}

export async function runStdioProxy(options: StdioProxyOptions = {}): Promise<void> {
  const env = options.env ?? process.env;
  const token = (options.token ?? env.COMPUTER_HISTORY_TOKEN ?? env.COMPUTER_ACCESS_TOKEN ?? '').trim();
  if (!token) {
    throw new Error('Missing COMPUTER_HISTORY_TOKEN environment variable.');
  }

  const rawUrl = (options.url ?? env.COMPUTER_HISTORY_URL ?? env.COMPUTER_ACCESS_URL ?? DEFAULT_STDIO_MCP_URL).trim();
  const targetUrl = validateLoopbackMcpUrl(rawUrl);

  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const errorOutput = options.errorOutput ?? process.stderr;
  const fetchFn = options.fetchImpl ?? fetch;

  const rl = createInterface({
    input,
    crlfDelay: Infinity,
  });

  for await (const rawLine of rl) {
    const line = rawLine.trim();
    if (line === '') {
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      await writeLine(output, {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      });
      continue;
    }

    let response: Response;
    try {
      response = await fetchFn(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: line,
      });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      errorOutput.write(`computer-history-mcp stdio upstream error: ${detail}\n`);
      const errPayload = buildSynthesizedError(parsed, -32002, `MCP upstream unreachable: ${detail}`);
      if (errPayload !== null) {
        await writeLine(output, errPayload);
      }
      continue;
    }

    const bodyText = await response.text();

    if (response.status === 202) {
      continue;
    }

    if (response.ok) {
      if (bodyText.trim() === '') {
        continue;
      }
      try {
        const json = JSON.parse(bodyText) as unknown;
        await writeLine(output, json);
      } catch {
        const errPayload = buildSynthesizedError(parsed, -32603, 'Invalid JSON response from MCP server');
        if (errPayload !== null) {
          await writeLine(output, errPayload);
        }
      }
      continue;
    }

    let parsedErrBody: Record<string, unknown> | null = null;
    try {
      const candidate = JSON.parse(bodyText) as unknown;
      if (candidate !== null && typeof candidate === 'object' && !Array.isArray(candidate)) {
        parsedErrBody = candidate as Record<string, unknown>;
      }
    } catch {
      parsedErrBody = null;
    }

    if (parsedErrBody && parsedErrBody.jsonrpc === '2.0' && 'error' in parsedErrBody) {
      await writeLine(output, parsedErrBody);
      continue;
    }

    const errReason =
      typeof parsedErrBody?.error === 'string'
        ? parsedErrBody.error
        : response.statusText || 'request-failed';
    const rpcCode = response.status === 401 ? -32001 : -32000;
    const synthesized = buildSynthesizedError(
      parsed,
      rpcCode,
      `HTTP ${response.status}: ${errReason}`,
      { status: response.status },
    );
    if (synthesized !== null) {
      await writeLine(output, synthesized);
    }
  }
}
