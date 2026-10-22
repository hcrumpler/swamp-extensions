/**
 * Model: @hmcrum/nfl-player-stats — real NFL player box-score statistics from
 * ESPN's public, unauthenticated summary endpoint.
 *
 * The missing middle layer: `@hmcrum/nfl-scores` has the games (final score,
 * status), `@hmcrum/nfl-injuries` has who's hurt, and `@dougschaefer/sleeper`
 * has the fantasy rosters — but none of them answer "how many yards did my
 * running back actually get?" This model does, straight from the same per-game
 * box score ESPN renders on its site.
 *
 * Two read-only methods:
 *
 *  - `box_score` — given one `event` id, fan out one resource per team, each
 *    holding every player's stat line grouped by category (passing, rushing,
 *    receiving, defensive, kicking, ...)
 *  - `week_stats` — given a week (or the current week), resolve the scoreboard
 *    to its completed games and emit one resource per game, each carrying both
 *    teams' player stat lines. Saves the caller from hunting event ids by hand.
 *
 * Same guarantee as `nfl_scores.ts`: every fetch goes through `guardedFetch`,
 * which refuses any hostname outside ALLOWED_HOSTS and re-checks after
 * redirects. Both methods read only `site.api.espn.com`, the versioned JSON API
 * (the same host `nfl_scores.ts` already uses). No auth, no secrets.
 *
 * ESPN encodes each stat category as parallel `labels` / `keys` / `athletes`
 * arrays — a player's `stats[i]` lines up with the category's `keys[i]` and
 * `labels[i]`. This model zips those back together into named `{key,label,
 * value}` triples so a consumer never has to track positional indexes.
 *
 * @module
 */
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// The allowlist. Nothing in this file reaches the network except through it.
// ---------------------------------------------------------------------------

const ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  "site.api.espn.com",
]);

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
 * Retry-After — ESPN's public endpoints are someone else's free server.
 */
async function guardedFetch(
  url: string,
  userAgent: string,
  attempts = 3,
): Promise<Response> {
  const target = assertAllowed(url);
  let wait = 700;
  for (let i = 0; i < attempts; i++) {
    const res = await fetch(target, {
      headers: { "User-Agent": userAgent, Accept: "application/json" },
      redirect: "follow",
    });
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

function str(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s.length > 0 ? s : null;
}

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  userAgent: z.string().default(
    "swamp-nfl-player-stats/1.0 (+https://github.com/swamp-club/swamp)",
  ).describe(
    "User-Agent sent to ESPN's endpoints — identify yourself honestly",
  ),
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

const SEASON_TYPES = { pre: 1, regular: 2, post: 3 } as const;

// ---------------------------------------------------------------------------
// Shared box-score shapes
// ---------------------------------------------------------------------------

/** One named statistic for one player: ESPN's positional key/label/value zipped. */
const StatSchema = z.object({
  key: z.string(),
  label: z.string(),
  value: z.string(),
});

/** One player's full line within a single category (e.g. all passing stats). */
const PlayerLineSchema = z.object({
  athleteId: z.string(),
  displayName: z.string(),
  position: z.string().nullable(),
  stats: z.array(StatSchema),
});

/** One stat category (passing, rushing, ...) with every player who recorded it. */
const CategorySchema = z.object({
  name: z.string(),
  players: z.array(PlayerLineSchema),
});

/** One team's complete box score: every category, every player. */
const TeamBoxScoreSchema = z.object({
  eventId: z.string(),
  teamId: z.string(),
  abbreviation: z.string(),
  displayName: z.string(),
  homeAway: z.enum(["home", "away"]).nullable(),
  categories: z.array(CategorySchema),
  fetchedAt: z.string(),
});

/** A whole game's player stats: both teams side by side. */
const GameStatsSchema = z.object({
  eventId: z.string(),
  name: z.string(),
  shortName: z.string(),
  date: z.string().nullable(),
  season: z.number().nullable(),
  seasonType: z.number().nullable(),
  week: z.number().nullable(),
  completed: z.boolean(),
  teams: z.array(TeamBoxScoreSchema),
  fetchedAt: z.string(),
});

// ---------------------------------------------------------------------------
// Raw ESPN shapes (summary endpoint)
// ---------------------------------------------------------------------------

interface RawAthleteStat {
  athlete?: {
    id?: string;
    displayName?: string;
    position?: { abbreviation?: string };
  };
  stats?: unknown[];
}

interface RawStatCategory {
  name?: string;
  labels?: string[];
  keys?: string[];
  athletes?: RawAthleteStat[];
}

interface RawPlayersTeam {
  team?: {
    id?: string;
    abbreviation?: string;
    displayName?: string;
    homeAway?: string;
  };
  statistics?: RawStatCategory[];
}

interface RawCompetitor {
  homeAway?: "home" | "away";
  team?: { id?: string };
}

interface RawSummary {
  boxscore?: { players?: RawPlayersTeam[] };
  header?: {
    id?: string;
    season?: { year?: number; type?: number };
    week?: { number?: number };
    competitions?: Array<{
      date?: string;
      status?: { type?: { completed?: boolean } };
      competitors?: RawCompetitor[];
    }>;
  };
}

/**
 * Zip ESPN's parallel `keys`/`labels`/`stats` arrays into named triples. The
 * three arrays are positional and sometimes differ in length across ESPN
 * revisions, so we iterate to the shortest and tolerate missing cells rather
 * than trusting them to line up.
 */
function zipStats(
  keys: string[] | undefined,
  labels: string[] | undefined,
  stats: unknown[] | undefined,
): Array<z.infer<typeof StatSchema>> {
  const k = Array.isArray(keys) ? keys : [];
  const l = Array.isArray(labels) ? labels : [];
  const s = Array.isArray(stats) ? stats : [];
  const n = Math.max(k.length, l.length, s.length);
  const out: Array<z.infer<typeof StatSchema>> = [];
  for (let i = 0; i < n; i++) {
    const value = str(s[i]);
    if (value === null) continue;
    out.push({
      key: str(k[i]) ?? `stat${i}`,
      label: str(l[i]) ?? str(k[i]) ?? `stat${i}`,
      value,
    });
  }
  return out;
}

/** Turn one team's raw `statistics` block into typed categories + player lines. */
function toCategories(
  statistics: RawStatCategory[] | undefined,
): Array<z.infer<typeof CategorySchema>> {
  const cats = Array.isArray(statistics) ? statistics : [];
  const out: Array<z.infer<typeof CategorySchema>> = [];
  for (const cat of cats) {
    const name = str(cat.name);
    if (!name) continue;
    const players: Array<z.infer<typeof PlayerLineSchema>> = [];
    for (const a of cat.athletes ?? []) {
      const athleteId = str(a.athlete?.id);
      if (!athleteId) continue;
      players.push({
        athleteId,
        displayName: str(a.athlete?.displayName) ?? "",
        position: str(a.athlete?.position?.abbreviation),
        stats: zipStats(cat.keys, cat.labels, a.stats),
      });
    }
    out.push({ name, players });
  }
  return out;
}

/**
 * Parse a full `summary?event=` response into per-team box scores plus the
 * game-level metadata needed to name and label the resources. `homeAway` is
 * recovered by matching each players-block team id against the header's
 * competitors (the players block itself doesn't carry home/away).
 */
function parseSummary(body: RawSummary, fallbackEventId: string): {
  game: Omit<z.infer<typeof GameStatsSchema>, "teams" | "fetchedAt">;
  teams: Array<Omit<z.infer<typeof TeamBoxScoreSchema>, "fetchedAt">>;
} {
  const header = body.header;
  const comp = header?.competitions?.[0];
  const eventId = str(header?.id) ?? fallbackEventId;

  const homeAwayById = new Map<string, "home" | "away">();
  for (const c of comp?.competitors ?? []) {
    const id = str(c.team?.id);
    if (id && (c.homeAway === "home" || c.homeAway === "away")) {
      homeAwayById.set(id, c.homeAway);
    }
  }

  const playersBlocks = Array.isArray(body.boxscore?.players)
    ? body.boxscore!.players!
    : [];

  const teams = playersBlocks.flatMap((
    block,
  ): Array<Omit<z.infer<typeof TeamBoxScoreSchema>, "fetchedAt">> => {
    const teamId = str(block.team?.id);
    if (!teamId) return [];
    return [{
      eventId,
      teamId,
      abbreviation: str(block.team?.abbreviation) ?? "",
      displayName: str(block.team?.displayName) ?? "",
      homeAway: homeAwayById.get(teamId) ?? null,
      categories: toCategories(block.statistics),
    }];
  });

  const abbrs = teams.map((t) => t.abbreviation).filter((a) => a.length > 0);
  // ESPN orders the players block away-team-first; derive a readable name.
  const name = abbrs.length === 2 ? `${abbrs[0]} @ ${abbrs[1]}` : "";

  return {
    game: {
      eventId,
      name,
      shortName: name,
      date: str(comp?.date),
      season: typeof header?.season?.year === "number"
        ? header.season.year
        : null,
      seasonType: typeof header?.season?.type === "number"
        ? header.season.type
        : null,
      week: typeof header?.week?.number === "number"
        ? header.week.number
        : null,
      completed: comp?.status?.type?.completed === true,
    },
    teams,
  };
}

// ---------------------------------------------------------------------------
// box_score
// ---------------------------------------------------------------------------

const BoxScoreArgsSchema = z.object({
  event: z.string().min(1).describe(
    "ESPN event (game) id, e.g. 401772939 — from nfl-scores `scoreboard` or the week_stats method",
  ),
});

type BoxScoreArgs = z.infer<typeof BoxScoreArgsSchema>;

// ---------------------------------------------------------------------------
// week_stats
// ---------------------------------------------------------------------------

const WeekStatsArgsSchema = z.object({
  week: z.number().int().min(1).max(22).optional().describe(
    "Week number within the season type — omit for the current week",
  ),
  seasonType: z.enum(["pre", "regular", "post"]).optional().describe(
    "pre, regular, or post — omit for whatever is currently in progress",
  ),
  year: z.number().int().min(1990).optional().describe(
    "Season year, e.g. 2025 — omit for the current season",
  ),
  includeIncomplete: z.boolean().optional().describe(
    "Also fetch stats for games that haven't finished (default false — only completed games)",
  ),
});

type WeekStatsArgs = z.infer<typeof WeekStatsArgsSchema>;

interface RawScoreboardEvent {
  id?: string;
  competitions?: Array<{
    status?: { type?: { completed?: boolean } };
  }>;
}

const SUMMARY_URL =
  "https://site.api.espn.com/apis/site/v2/sports/football/nfl/summary";
const SCOREBOARD_URL =
  "https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard";

/** The `@hmcrum/nfl-player-stats` model: per-game player box scores from ESPN. */
export const model = {
  type: "@hmcrum/nfl-player-stats",
  version: "2026.10.22.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    teamBoxScore: {
      description:
        "One NFL team's player stat lines for a single game, grouped by category",
      schema: TeamBoxScoreSchema,
      lifetime: "24h" as const,
      garbageCollection: 20,
    },
    gameStats: {
      description:
        "Both teams' player stat lines for a single NFL game, side by side",
      schema: GameStatsSchema,
      lifetime: "24h" as const,
      garbageCollection: 20,
    },
  },

  methods: {
    box_score: {
      description:
        "Fetch one game's player box score by event id — fans out one resource per team",
      arguments: BoxScoreArgsSchema,
      execute: async (args: BoxScoreArgs, context: ExecContext) => {
        const g = context.globalArgs;
        const res = await guardedFetch(
          `${SUMMARY_URL}?event=${encodeURIComponent(args.event)}`,
          g.userAgent,
        );

        if (!res.ok) {
          const body = await res.text().catch(() => "");
          throw new Error(
            `ESPN summary request for event ${args.event} returned ${res.status}: ${body}`,
          );
        }

        const body = await res.json() as RawSummary;
        const { teams } = parseSummary(body, args.event);

        if (teams.length === 0) {
          throw new Error(
            `ESPN summary for event ${args.event} contained no player box score — is it a valid, played game?`,
          );
        }

        const now = new Date().toISOString();
        const handles = [];
        for (const team of teams) {
          const instanceName = team.abbreviation
            ? `${team.eventId}-${team.abbreviation.toLowerCase()}`
            : `${team.eventId}-${team.teamId}`;
          const handle = await context.writeResource(
            "teamBoxScore",
            instanceName,
            { ...team, fetchedAt: now },
          );
          handles.push(handle);
        }

        context.logger.info(
          `nfl player stats: box score for event ${args.event} — ${handles.length} team(s)`,
        );
        return { dataHandles: handles };
      },
    },

    week_stats: {
      description:
        "Resolve a week's games and fetch each one's player box score — one resource per game, defaults to the current week and completed games only",
      arguments: WeekStatsArgsSchema,
      execute: async (args: WeekStatsArgs, context: ExecContext) => {
        const g = context.globalArgs;

        const params = new URLSearchParams();
        if (args.week !== undefined) params.set("week", String(args.week));
        if (args.seasonType !== undefined) {
          params.set("seasontype", String(SEASON_TYPES[args.seasonType]));
        }
        if (args.year !== undefined) params.set("dates", String(args.year));
        const qs = params.toString();

        const sbRes = await guardedFetch(
          `${SCOREBOARD_URL}${qs ? `?${qs}` : ""}`,
          g.userAgent,
        );
        if (!sbRes.ok) {
          const body = await sbRes.text().catch(() => "");
          throw new Error(
            `ESPN scoreboard request returned ${sbRes.status}: ${body}`,
          );
        }

        const sbBody = await sbRes.json() as { events?: RawScoreboardEvent[] };
        const events = Array.isArray(sbBody.events) ? sbBody.events : [];

        const wanted = events.filter((e) => {
          if (!str(e.id)) return false;
          if (args.includeIncomplete === true) return true;
          return e.competitions?.[0]?.status?.type?.completed === true;
        });

        context.logger.info(
          `nfl player stats: week has ${events.length} game(s), ${wanted.length} to fetch`,
        );

        const now = new Date().toISOString();
        const handles = [];
        let failures = 0;
        for (const ev of wanted) {
          const eventId = str(ev.id)!;
          try {
            const res = await guardedFetch(
              `${SUMMARY_URL}?event=${encodeURIComponent(eventId)}`,
              g.userAgent,
            );
            if (!res.ok) {
              await res.body?.cancel();
              failures++;
              context.logger.warning(
                `nfl player stats: summary for event ${eventId} returned ${res.status}, skipping`,
              );
              continue;
            }
            const body = await res.json() as RawSummary;
            const { game, teams } = parseSummary(body, eventId);
            if (teams.length === 0) {
              failures++;
              context.logger.warning(
                `nfl player stats: event ${eventId} had no player box score, skipping`,
              );
              continue;
            }
            const teamsWithTime = teams.map((t) => ({ ...t, fetchedAt: now }));
            const handle = await context.writeResource(
              "gameStats",
              eventId,
              { ...game, teams: teamsWithTime, fetchedAt: now },
            );
            handles.push(handle);
          } catch (err) {
            failures++;
            context.logger.warning(
              `nfl player stats: event ${eventId} failed: ${
                err instanceof Error ? err.message : String(err)
              }`,
            );
          }
        }

        if (handles.length === 0 && wanted.length > 0) {
          throw new Error(
            `nfl player stats: all ${wanted.length} game(s) failed to fetch`,
          );
        }

        context.logger.info(
          `nfl player stats: wrote ${handles.length} game(s), ${failures} skipped`,
        );
        return { dataHandles: handles };
      },
    },
  },
};
