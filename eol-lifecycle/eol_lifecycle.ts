/**
 * Model: @hmcrum/eol-lifecycle — support/end-of-life lifecycle lookups
 * against the public endoflife.date API.
 *
 * Same guarantee as `jw_research.ts`: every fetch goes through `guardedFetch`,
 * which refuses any hostname outside ALLOWED_HOSTS and re-checks after
 * redirects, so a 302 cannot walk the run off endoflife.date onto anywhere
 * else. No auth, no secrets — this is a public, read-only API.
 *
 * One method, `lifecycle`. The product name is always supplied by the caller;
 * nothing about any specific product is hardcoded. A product endoflife.date
 * does not recognize is not an error condition worth throwing over — it is
 * the single most likely input, so it degrades to an empty result carrying a
 * `note` and, where possible, close-match `suggestions` pulled from the
 * catalog at `/all.json`.
 *
 * endoflife.date's own `eol` field is contractually a date string OR the
 * boolean `false` (never ends) or `true` (already ended, no date on record).
 * `supported` is computed from that against "now" so callers get one clean
 * boolean instead of three-way logic repeated at every call site.
 *
 * Source: https://endoflife.date/api (docs: https://endoflife.date/docs/api)
 *
 * @module
 */
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// The allowlist. Nothing in this file reaches the network except through it.
// ---------------------------------------------------------------------------

const ALLOWED_HOSTS: ReadonlySet<string> = new Set(["endoflife.date"]);

/** Throws unless `url` is HTTPS on an allowlisted host. Returns the parsed URL. */
function assertAllowed(url: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`refusing unparseable URL: ${url}`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`refusing non-HTTPS URL: ${url}`);
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error(
      `refusing ${parsed.hostname}: this model reads only ${
        [...ALLOWED_HOSTS].join(", ")
      }`,
    );
  }
  return parsed;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * The only network call in this module. Enforces the allowlist before the
 * request AND after redirects, retries 429/5xx with backoff, and honours
 * Retry-After — endoflife.date is someone else's free public server.
 */
async function guardedFetch(
  url: string,
  userAgent: string,
  headers: Record<string, string> = {},
  attempts = 3,
): Promise<Response> {
  const target = assertAllowed(url);
  let wait = 700;
  for (let i = 0; i < attempts; i++) {
    const res = await fetch(target, {
      headers: {
        "User-Agent": userAgent,
        Accept: "application/json",
        ...headers,
      },
      redirect: "follow",
    });
    // A redirect must not have carried us off the allowlist.
    if (res.url) assertAllowed(res.url);
    if (res.status !== 429 && res.status < 500) return res;
    if (i === attempts - 1) return res;
    const retryAfter = Number(res.headers.get("retry-after"));
    await res.body?.cancel();
    await sleep(
      Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : wait,
    );
    wait *= 2;
  }
  throw new Error("unreachable");
}

// ---------------------------------------------------------------------------
// endoflife.date wire shapes (only the fields this model reads)
// ---------------------------------------------------------------------------

interface RawCycle {
  cycle?: string | number;
  releaseDate?: string | null;
  eol?: string | boolean;
  latest?: string | null;
  latestReleaseDate?: string | null;
  lts?: string | boolean;
  discontinued?: string | boolean;
  link?: string | null;
}

function str(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s.length > 0 ? s : null;
}

/** endoflife.date's `eol`/`discontinued`/`lts` fields: a date string, or a bare boolean. */
function boolOrDate(v: unknown): string | boolean | null {
  if (typeof v === "boolean") return v;
  const s = str(v);
  return s;
}

/** `false` = never ends, `true` = already ended (no date on record), a string = ends that day. */
function isEol(eol: string | boolean | null, now: Date): boolean {
  if (typeof eol === "boolean") return eol;
  if (eol === null) return false;
  const parsed = new Date(eol);
  if (Number.isNaN(parsed.getTime())) return false;
  return parsed.getTime() <= now.getTime();
}

/** Slugify for a resource name — lowercase, non-alnum collapsed to dashes. */
function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

/**
 * Close matches for a product name that endoflife.date didn't recognize,
 * drawn from the live catalog at `/all.json` rather than any hardcoded list —
 * catalog substring match first, falling back to a shared-prefix match, so a
 * typo like "ubunut" still surfaces "ubuntu".
 */
function closeMatches(product: string, catalog: string[], limit = 5): string[] {
  const needle = product.toLowerCase();
  const substring = catalog.filter((p) =>
    p.includes(needle) || needle.includes(p)
  );
  if (substring.length > 0) return substring.slice(0, limit);
  const prefix = needle.slice(0, 3);
  if (prefix.length < 2) return [];
  return catalog.filter((p) => p.startsWith(prefix)).slice(0, limit);
}

// ---------------------------------------------------------------------------
// Resource schema
// ---------------------------------------------------------------------------

const CycleSchema = z.object({
  cycle: z.string(),
  releaseDate: z.string().nullable(),
  /** Raw `eol` field from the API — a date string, or the boolean it can also be. */
  eolDate: z.union([z.string(), z.boolean()]).nullable(),
  latest: z.string().nullable(),
  /** Computed from `eolDate` against the current date — the one field callers need. */
  supported: z.boolean(),
});

const LifecycleSchema = z.object({
  product: z.string(),
  found: z.boolean(),
  requestedCycle: z.string().nullable(),
  cycles: z.array(CycleSchema),
  /** True if any cycle in `cycles` (i.e. matching `requestedCycle`, when given) is past EOL. */
  anyEol: z.boolean(),
  /** Set whenever the result degraded — product not found, or requested cycle missing. */
  note: z.string().nullable(),
  /** Close matches from endoflife.date's own catalog, only populated when `found` is false. */
  suggestions: z.array(z.string()),
  fetchedAt: z.string(),
});

const GlobalArgsSchema = z.object({
  userAgent: z.string().default(
    "swamp-eol-lifecycle/1.0 (+https://github.com/swamp-club/swamp)",
  ).describe("User-Agent sent to endoflife.date — identify yourself honestly"),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

interface ExecContext {
  globalArgs: GlobalArgs;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warning: (msg: string, props?: Record<string, unknown>) => void;
  };
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** The `@hmcrum/eol-lifecycle` model: one `lifecycle` method against endoflife.date. */
export const model = {
  type: "@hmcrum/eol-lifecycle",
  version: "2026.09.17.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    lifecycle: {
      description:
        "Support/end-of-life lifecycle for one product from endoflife.date, with a computed supported boolean per release cycle",
      schema: LifecycleSchema,
      lifetime: "30m" as const,
      garbageCollection: 5,
    },
  },

  methods: {
    lifecycle: {
      description:
        "Look up the release-cycle lifecycle (release date, EOL date, latest version, computed support status) for a product on endoflife.date. Degrades to an empty, noted result on an unrecognized product instead of throwing.",
      arguments: z.object({
        product: z.string().min(1).describe(
          "endoflife.date product identifier, e.g. python, ubuntu, postgresql",
        ),
        cycle: z.string().optional().describe(
          "Narrow to one release cycle, e.g. '3.11' — omit for every cycle",
        ),
      }),
      execute: async (
        args: { product: string; cycle?: string },
        context: ExecContext,
      ) => {
        const g = context.globalArgs;
        const product = args.product.trim();
        const now = new Date();

        const res = await guardedFetch(
          `https://endoflife.date/api/${encodeURIComponent(product)}.json`,
          g.userAgent,
        );

        if (res.status === 404) {
          await res.body?.cancel();
          let suggestions: string[] = [];
          try {
            const allRes = await guardedFetch(
              "https://endoflife.date/api/all.json",
              g.userAgent,
            );
            if (allRes.ok) {
              const all = await allRes.json() as unknown[];
              suggestions = closeMatches(product, all.map((p) => String(p)));
            } else {
              await allRes.body?.cancel();
            }
          } catch (e) {
            context.logger.warning(
              `endoflife.date /all.json lookup failed while suggesting matches for "${product}": ${
                e instanceof Error ? e.message : String(e)
              }`,
            );
          }

          const note = suggestions.length > 0
            ? `endoflife.date has no product "${product}". Close matches: ${
              suggestions.join(", ")
            }.`
            : `endoflife.date has no product "${product}" and no close match was found in its catalog.`;

          context.logger.info(
            `eol lifecycle: product "${product}" not found on endoflife.date`,
          );

          const handle = await context.writeResource(
            "lifecycle",
            `lifecycle-${slug(product)}`,
            {
              product,
              found: false,
              requestedCycle: args.cycle ?? null,
              cycles: [],
              anyEol: false,
              note,
              suggestions,
              fetchedAt: now.toISOString(),
            },
          );
          return { dataHandles: [handle] };
        }

        if (!res.ok) {
          const body = await res.text().catch(() => "");
          throw new Error(
            `endoflife.date returned ${res.status} for "${product}": ${body}`,
          );
        }

        const body = await res.json();
        const raw: RawCycle[] = Array.isArray(body)
          ? body
          : Array.isArray((body as { result?: unknown }).result)
          ? (body as { result: RawCycle[] }).result
          : [];

        const allCycles = raw.map((c): z.infer<typeof CycleSchema> => {
          const eolDate = boolOrDate(c.eol);
          return {
            cycle: String(c.cycle ?? "").trim(),
            releaseDate: str(c.releaseDate),
            eolDate,
            latest: str(c.latest),
            supported: !isEol(eolDate, now),
          };
        });

        let cycles = allCycles;
        let note: string | null = null;
        if (args.cycle) {
          const wanted = args.cycle.trim();
          cycles = allCycles.filter((c) => c.cycle === wanted);
          if (cycles.length === 0) {
            note =
              `product "${product}" was found, but has no cycle "${wanted}". Available cycles: ${
                allCycles.map((c) => c.cycle).join(", ") || "(none)"
              }.`;
          }
        }

        const anyEol = cycles.some((c) => !c.supported);

        context.logger.info(
          `eol lifecycle: ${product} — ${cycles.length}/${allCycles.length} cycle(s), anyEol=${anyEol}`,
        );

        const handle = await context.writeResource(
          "lifecycle",
          `lifecycle-${slug(product)}${
            args.cycle ? `-${slug(args.cycle)}` : ""
          }`,
          {
            product,
            found: true,
            requestedCycle: args.cycle ?? null,
            cycles,
            anyEol,
            note,
            suggestions: [] as string[],
            fetchedAt: now.toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
