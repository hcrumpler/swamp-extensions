/**
 * Model: @hmcrum/tls-cert-expiry — standalone TLS certificate expiry checker.
 *
 * Unlike @lint/cert-health (whose `probe` method does the same handshake but
 * lives behind globalArguments that require Nginx Proxy Manager credentials
 * even when you never touch NPM), this model has no external dependency: give
 * it hostnames, get back days-until-expiry. One method, `check`, TLS-connects
 * to each host (via `openssl s_client`, the same probing idiom @lint/cert-health
 * uses, since Deno has no public API for reading a peer's certificate chain),
 * classifies each by days remaining against configurable thresholds, and
 * writes one resource per host plus a fleet-wide summary.
 *
 * Per-host probe failures (unreachable host, TLS handshake failure, timeout)
 * degrade to a `status: "error"` result for that host rather than aborting the
 * whole batch — one dead host shouldn't hide the results for the other 49.
 *
 * @module
 */
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Pure helpers — no I/O, fully unit-testable.
// ---------------------------------------------------------------------------

/** Splits "host" or "host:port" into parts. A non-numeric suffix is treated as part of the host. */
export function parseHostPort(
  entry: string,
  defaultPort: number,
): { host: string; port: number } {
  const idx = entry.lastIndexOf(":");
  if (idx > 0) {
    const maybePort = entry.slice(idx + 1);
    if (/^\d+$/.test(maybePort)) {
      return { host: entry.slice(0, idx), port: Number(maybePort) };
    }
  }
  return { host: entry, port: defaultPort };
}

/**
 * Parses the line-oriented output of `openssl x509 -noout -enddate -startdate -subject -issuer -serial
 * -fingerprint -sha256`. `serial` is uppercase hex; `fingerprintSha256` is lowercase hex without colons.
 */
export function parseX509Fields(text: string): {
  notBefore: string | null;
  notAfter: string | null;
  subject: string | null;
  issuer: string | null;
  serial: string | null;
  fingerprintSha256: string | null;
} {
  const notAfter = text.match(/^notAfter=(.+)$/m);
  const notBefore = text.match(/^notBefore=(.+)$/m);
  const subject = text.match(/^subject=[ \t]*(\S.*)$/m);
  const issuer = text.match(/^issuer=[ \t]*(\S.*)$/m);
  const serial = text.match(/^serial=([0-9A-Fa-f]+)\s*$/m);
  const fingerprint = text.match(/^sha256 fingerprint=([0-9A-Fa-f:]+)\s*$/im);
  return {
    serial: serial ? serial[1].toUpperCase() : null,
    fingerprintSha256: fingerprint
      ? fingerprint[1].replaceAll(":", "").toLowerCase()
      : null,
    notAfter: notAfter ? notAfter[1].trim() : null,
    notBefore: notBefore ? notBefore[1].trim() : null,
    subject: subject ? subject[1].trim() : null,
    issuer: issuer ? issuer[1].trim() : null,
  };
}

/** Whole days between `now` and the certificate's `notAfter`. Negative once expired. */
export function computeDaysRemaining(
  notAfter: string | null,
  now: Date,
): number | null {
  if (!notAfter) return null;
  const parsed = new Date(notAfter);
  if (Number.isNaN(parsed.getTime())) return null;
  return Math.floor((parsed.getTime() - now.getTime()) / 86_400_000);
}

export type CertStatus = "ok" | "warn" | "critical" | "error";

/** A probe error (or an unparseable expiry date) always classifies as "error", never a threshold band. */
export function classifyStatus(
  daysRemaining: number | null,
  hasError: boolean,
  warnThresholdDays: number,
  criticalThresholdDays: number,
): CertStatus {
  if (hasError || daysRemaining === null) return "error";
  if (daysRemaining <= criticalThresholdDays) return "critical";
  if (daysRemaining <= warnThresholdDays) return "warn";
  return "ok";
}

export type Verdict = "ok" | "other-certificate" | "expiring" | "unreachable";

/** Lowercase hex without colons or whitespace; throws unless the result is 64 hex characters. */
export function normalizeFingerprint(value: string): string {
  const fp = value.replace(/[:\s]/g, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(fp)) {
    throw new Error(
      `expectFingerprint must be a SHA-256 fingerprint (64 hex characters, colons optional), got "${value}"`,
    );
  }
  return fp;
}

/** First match wins: unreachable, then other-certificate, then expiring, else ok. `expectFingerprint` must be normalised. */
export function computeVerdict(
  r: Pick<
    CertResult,
    "host" | "port" | "daysRemaining" | "fingerprintSha256" | "error"
  >,
  expectFingerprint: string | undefined,
  minDays: number | undefined,
): { verdict: Verdict; cause: string | null } {
  const at = `${r.host}:${r.port}`;
  if (r.error !== null || r.fingerprintSha256 === null) {
    return {
      verdict: "unreachable",
      cause: r.error ?? `${at} returned no certificate`,
    };
  }
  if (
    expectFingerprint !== undefined && r.fingerprintSha256 !== expectFingerprint
  ) {
    return {
      verdict: "other-certificate",
      cause:
        `${at} serves certificate ${r.fingerprintSha256}, expected ${expectFingerprint}`,
    };
  }
  if (minDays !== undefined && (r.daysRemaining ?? -1) < minDays) {
    return {
      verdict: "expiring",
      cause: `${at} certificate has ${
        r.daysRemaining ?? "unknown"
      } day(s) left, minDays is ${minDays}`,
    };
  }
  return { verdict: "ok", cause: null };
}

/** Slugify for a resource instance name — lowercase, non-alnum collapsed to dashes. */
function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const CertResultSchema = z.object({
  host: z.string(),
  port: z.number(),
  status: z.enum(["ok", "warn", "critical", "error"]),
  daysRemaining: z.number().int().nullable(),
  notBefore: z.string().nullable(),
  notAfter: z.string().nullable(),
  subject: z.string().nullable(),
  issuer: z.string().nullable(),
  serial: z.string().nullable(),
  fingerprintSha256: z.string().nullable(),
  error: z.string().nullable(),
  verdict: z.enum(["ok", "other-certificate", "expiring", "unreachable"]),
  cause: z.string().nullable(),
  checkedAt: z.iso.datetime(),
});
type CertResult = z.infer<typeof CertResultSchema>;

const SummarySchema = z.object({
  total: z.number().int(),
  ok: z.number().int(),
  warn: z.number().int(),
  critical: z.number().int(),
  error: z.number().int(),
  closestToExpiry: z.array(CertResultSchema),
  /** True when more resolvable hosts exist than `closestToExpiry` shows (capped at `topN`). */
  truncated: z.boolean(),
  checkedAt: z.iso.datetime(),
});

/** Ranks by soonest expiry first; unresolvable results (no daysRemaining) are excluded, not ranked last. */
export function buildSummary(
  results: CertResult[],
  now: Date,
  topN = 10,
): z.infer<typeof SummarySchema> {
  const counts = { ok: 0, warn: 0, critical: 0, error: 0 };
  for (const r of results) counts[r.status]++;
  const resolvable = results
    .filter((r) => r.daysRemaining !== null)
    .sort((a, b) => a.daysRemaining! - b.daysRemaining!);
  return {
    total: results.length,
    ...counts,
    closestToExpiry: resolvable.slice(0, topN),
    truncated: resolvable.length > topN,
    checkedAt: now.toISOString(),
  };
}

const GlobalArgsSchema = z.object({
  warnThresholdDays: z.number().int().positive().default(30).describe(
    "Days-remaining at or below which a cert is classified `warn`",
  ),
  criticalThresholdDays: z.number().int().positive().default(7).describe(
    "Days-remaining at or below which a cert is classified `critical`",
  ),
  timeoutSec: z.number().int().positive().default(10).describe(
    "Per-host TLS connect + handshake timeout",
  ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Probing — the only part of this file that touches a subprocess.
// ---------------------------------------------------------------------------

interface ProbeResult {
  x509Text: string | null;
  error: string | null;
}
type ProbeFn = (
  host: string,
  port: number,
  timeoutMs: number,
  serverName?: string,
) => Promise<ProbeResult>;

/** Runs `openssl <args>`, optionally feeding `input` to stdin, killing the process past `timeoutMs`. */
async function runOpenssl(
  args: string[],
  input: Uint8Array | null,
  timeoutMs: number,
): Promise<
  { stdout: string; stderr: string; success: boolean; timedOut: boolean }
> {
  const cmd = new Deno.Command("openssl", {
    args,
    stdin: input !== null ? "piped" : "null",
    stdout: "piped",
    stderr: "piped",
  });
  const child = cmd.spawn();
  if (input !== null) {
    const writer = child.stdin.getWriter();
    await writer.write(input);
    await writer.close();
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      child.kill("SIGKILL");
    } catch {
      // already exited
    }
  }, timeoutMs);
  const output = await child.output();
  clearTimeout(timer);
  return {
    stdout: new TextDecoder().decode(output.stdout),
    stderr: new TextDecoder().decode(output.stderr),
    success: output.success,
    timedOut,
  };
}

const CERT_PATTERN =
  /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

/** TLS-handshakes `host:port` via `openssl s_client`, then extracts leaf-cert fields via `openssl x509`. */
async function defaultProbe(
  host: string,
  port: number,
  timeoutMs: number,
  serverName?: string,
): Promise<ProbeResult> {
  const sClient = await runOpenssl(
    [
      "s_client",
      "-connect",
      `${host}:${port}`,
      "-servername",
      serverName ?? host,
    ],
    new Uint8Array(0),
    timeoutMs,
  );
  if (sClient.timedOut) {
    return {
      x509Text: null,
      error: `connection to ${host}:${port} timed out after ${timeoutMs}ms`,
    };
  }
  const certMatch = sClient.stdout.match(CERT_PATTERN);
  if (!certMatch) {
    const reason = sClient.stderr.trim() || sClient.stdout.trim() ||
      "no certificate returned";
    return {
      x509Text: null,
      error: `TLS handshake with ${host}:${port} failed: ${
        reason.slice(0, 300)
      }`,
    };
  }
  const x509 = await runOpenssl(
    [
      "x509",
      "-noout",
      "-enddate",
      "-startdate",
      "-subject",
      "-issuer",
      "-serial",
      "-fingerprint",
      "-sha256",
    ],
    new TextEncoder().encode(certMatch[0]),
    timeoutMs,
  );
  if (!x509.success) {
    return {
      x509Text: null,
      error:
        `failed to parse certificate for ${host}:${port}: ${x509.stderr.trim()}`,
    };
  }
  return { x509Text: x509.stdout, error: null };
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

interface ExecContext {
  globalArgs: GlobalArgs;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
  };
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

const CheckArgsSchema = z.object({
  hosts: z.array(z.string().min(1)).min(1).describe(
    "Hostnames to check. Use host:port to override defaultPort per entry.",
  ),
  defaultPort: z.number().int().min(1).max(65535).default(443).describe(
    "Port used for any host entry that doesn't specify its own",
  ),
  expectFingerprint: z.string().optional().describe(
    "SHA-256 fingerprint the served certificate must have (colons, spaces and case ignored); a different one gives verdict `other-certificate`",
  ),
  minDays: z.number().int().min(0).optional().describe(
    "Fewest days a certificate may have left; fewer gives verdict `expiring`",
  ),
  serverName: z.string().min(1).optional().describe(
    "SNI name to send instead of the host name",
  ),
});
type CheckArgs = z.infer<typeof CheckArgsSchema> & { _probe?: ProbeFn };

/** The probe, verdicts and writes shared by `check` and `verify`. */
async function probeAndWrite(args: CheckArgs, context: ExecContext) {
  const g = context.globalArgs;
  const timeoutMs = g.timeoutSec * 1000;
  const now = new Date();
  const probe = args._probe ?? defaultProbe;
  const expectFingerprint = args.expectFingerprint === undefined
    ? undefined
    : normalizeFingerprint(args.expectFingerprint);

  context.logger.info("tls-cert-expiry check: probing {count} host(s)", {
    count: args.hosts.length,
  });

  const results: CertResult[] = await Promise.all(
    args.hosts.map(async (entry): Promise<CertResult> => {
      const { host, port } = parseHostPort(entry, args.defaultPort);
      const { x509Text, error } = await probe(
        host,
        port,
        timeoutMs,
        args.serverName,
      );
      const fields = x509Text ? parseX509Fields(x509Text) : {
        notAfter: null,
        notBefore: null,
        subject: null,
        issuer: null,
        serial: null,
        fingerprintSha256: null,
      };
      const daysRemaining = computeDaysRemaining(fields.notAfter, now);
      const status = classifyStatus(
        daysRemaining,
        error !== null,
        g.warnThresholdDays,
        g.criticalThresholdDays,
      );
      return {
        host,
        port,
        status,
        daysRemaining,
        notBefore: fields.notBefore,
        notAfter: fields.notAfter,
        subject: fields.subject,
        issuer: fields.issuer,
        serial: fields.serial,
        fingerprintSha256: fields.fingerprintSha256,
        error,
        ...computeVerdict(
          { host, port, daysRemaining, error, ...fields },
          expectFingerprint,
          args.minDays,
        ),
        checkedAt: now.toISOString(),
      };
    }),
  );

  const handles = [];
  for (const r of results) {
    const handle = await context.writeResource(
      "cert",
      `cert-${slug(`${r.host}-${r.port}`)}`,
      r,
    );
    handles.push(handle);
  }

  const summary = buildSummary(results, now);
  handles.push(await context.writeResource("summary", "summary", summary));

  context.logger.info(
    "tls-cert-expiry check: {total} host(s) — ok={ok} warn={warn} critical={critical} error={error}",
    summary,
  );

  return { dataHandles: handles, results };
}

/** The `@hmcrum/tls-cert-expiry` model: one `check` method, no external dependency. */
export const model = {
  type: "@hmcrum/tls-cert-expiry",
  version: "2026.09.17.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    cert: {
      description:
        "Per-host TLS certificate result: expiry, days remaining, and classification",
      schema: CertResultSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    summary: {
      description:
        "Fleet-wide rollup: counts per status plus the hosts closest to expiry",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },

  methods: {
    check: {
      description:
        "TLS-handshake every listed host, classify each by days-until-expiry against warnThresholdDays/criticalThresholdDays, and write a per-host result plus a fleet-wide summary. Probe failures degrade to a per-host `error` status instead of aborting the batch.",
      arguments: CheckArgsSchema,
      execute: async (args: CheckArgs, context: ExecContext) => {
        const { dataHandles } = await probeAndWrite(args, context);
        return { dataHandles };
      },
    },
    verify: {
      description:
        "Run `check` on exactly one host and write the same results, then refuse with the `cause` unless its verdict is `ok`. Use expectFingerprint, minDays and serverName to say what must be served.",
      arguments: CheckArgsSchema,
      execute: async (args: CheckArgs, context: ExecContext) => {
        if (args.hosts.length !== 1) {
          throw new Error(
            `verify needs exactly one host, got ${args.hosts.length}`,
          );
        }
        const { dataHandles, results } = await probeAndWrite(args, context);
        if (results[0].cause !== null) throw new Error(results[0].cause);
        return { dataHandles };
      },
    },
  },
};
