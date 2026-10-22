/**
 * Tests for @hmcrum/nfl-player-stats.
 *
 * All fixtures are invented JSON shaped like ESPN's real `summary` and
 * `scoreboard` responses, not fetched from the live API — `withMockedFetch`
 * stands in for the network so these run offline and deterministically.
 *
 * @module
 */
import { assertEquals } from "jsr:@std/assert@1.0.8";
import {
  createModelTestContext,
  withMockedFetch,
} from "jsr:@swamp-club/swamp-testing@0.20260917.35";
import { model } from "./nfl_player_stats.ts";

type BoxScoreArgs = Parameters<typeof model.methods.box_score.execute>[0];
type WeekStatsArgs = Parameters<typeof model.methods.week_stats.execute>[0];
type ExecContext = Parameters<typeof model.methods.box_score.execute>[1];

/**
 * `createModelTestContext`'s `globalArgs` is typed `Record<string, unknown>`,
 * which can't structurally satisfy the model's narrower `{ userAgent: string }`
 * context type — these wrappers are the one cast that absorbs that mismatch.
 */
function runBoxScore(args: BoxScoreArgs, context: unknown) {
  return model.methods.box_score.execute(args, context as ExecContext);
}
function runWeekStats(args: WeekStatsArgs, context: unknown) {
  return model.methods.week_stats.execute(args, context as ExecContext);
}

function json(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200 });
}

/** A minimal but realistic two-team summary with one passing + one rushing line. */
function summaryFixture() {
  return {
    header: {
      id: "401772939",
      season: { year: 2025, type: 2 },
      week: { number: 5 },
      competitions: [
        {
          date: "2025-10-03T00:15Z",
          status: { type: { completed: true } },
          competitors: [
            { homeAway: "home", team: { id: "14" } },
            { homeAway: "away", team: { id: "25" } },
          ],
        },
      ],
    },
    boxscore: {
      players: [
        {
          team: { id: "25", abbreviation: "SF", displayName: "San Francisco 49ers" },
          statistics: [
            {
              name: "passing",
              labels: ["C/ATT", "YDS", "TD", "INT"],
              keys: [
                "completions/passingAttempts",
                "passingYards",
                "passingTouchdowns",
                "interceptions",
              ],
              athletes: [
                {
                  athlete: {
                    id: "4241464",
                    displayName: "Mac Jones",
                    position: { abbreviation: "QB" },
                  },
                  stats: ["33/49", "342", "2", "0"],
                },
              ],
            },
          ],
        },
        {
          team: { id: "14", abbreviation: "LAR", displayName: "Los Angeles Rams" },
          statistics: [
            {
              name: "rushing",
              labels: ["CAR", "YDS", "TD"],
              keys: ["rushingAttempts", "rushingYards", "rushingTouchdowns"],
              athletes: [
                {
                  athlete: {
                    id: "4361579",
                    displayName: "Kyren Williams",
                    position: { abbreviation: "RB" },
                  },
                  stats: ["14", "65", "1"],
                },
              ],
            },
          ],
        },
      ],
    },
  };
}

Deno.test("box_score fans out one resource per team, keyed event-abbrev", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { userAgent: "nfl-player-stats-test/1.0" },
  });

  await withMockedFetch(
    (req) => {
      const url = new URL(req.url);
      assertEquals(url.hostname, "site.api.espn.com");
      assertEquals(url.searchParams.get("event"), "401772939");
      return json(summaryFixture());
    },
    () => runBoxScore({ event: "401772939" } as unknown as BoxScoreArgs, context),
  );

  const written = getWrittenResources();
  assertEquals(written.length, 2);
  assertEquals(written.map((w) => w.name).sort(), [
    "401772939-lar",
    "401772939-sf",
  ]);
});

Deno.test("box_score zips keys/labels/stats into named triples and keeps home/away", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { userAgent: "nfl-player-stats-test/1.0" },
  });

  await withMockedFetch(
    () => json(summaryFixture()),
    () => runBoxScore({ event: "401772939" } as unknown as BoxScoreArgs, context),
  );

  const sf = getWrittenResources().find((w) => w.name === "401772939-sf")
    ?.data as {
      homeAway: string | null;
      categories: Array<
        { name: string; players: Array<{ stats: Array<Record<string, string>> }> }
      >;
    };

  assertEquals(sf.homeAway, "away");
  assertEquals(sf.categories[0].name, "passing");
  const stats = sf.categories[0].players[0].stats;
  assertEquals(stats[0], {
    key: "completions/passingAttempts",
    label: "C/ATT",
    value: "33/49",
  });
  assertEquals(stats[1], { key: "passingYards", label: "YDS", value: "342" });

  const lar = getWrittenResources().find((w) => w.name === "401772939-lar")
    ?.data as { homeAway: string | null };
  assertEquals(lar.homeAway, "home");
});

Deno.test("box_score throws (writing nothing) when the box score has no players", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { userAgent: "nfl-player-stats-test/1.0" },
  });

  let threw = false;
  await withMockedFetch(
    () => json({ header: { id: "1" }, boxscore: { players: [] } }),
    async () => {
      try {
        await runBoxScore({ event: "1" } as unknown as BoxScoreArgs, context);
      } catch {
        threw = true;
      }
    },
  );

  assertEquals(threw, true);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("box_score throws on a non-OK response instead of writing a resource", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { userAgent: "nfl-player-stats-test/1.0" },
  });

  let threw = false;
  await withMockedFetch(
    () => new Response("upstream on fire", { status: 500 }),
    async () => {
      try {
        await runBoxScore({ event: "99" } as unknown as BoxScoreArgs, context);
      } catch {
        threw = true;
      }
    },
  );

  assertEquals(threw, true);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("week_stats fetches only completed games by default, one resource each", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { userAgent: "nfl-player-stats-test/1.0" },
  });

  await withMockedFetch(
    (req) => {
      const url = new URL(req.url);
      assertEquals(url.hostname, "site.api.espn.com");
      if (url.pathname.endsWith("/scoreboard")) {
        return json({
          events: [
            {
              id: "401772939",
              competitions: [{ status: { type: { completed: true } } }],
            },
            {
              id: "401772640",
              competitions: [{ status: { type: { completed: false } } }],
            },
          ],
        });
      }
      // summary for the one completed game
      assertEquals(url.searchParams.get("event"), "401772939");
      return json(summaryFixture());
    },
    () => runWeekStats({} as unknown as WeekStatsArgs, context),
  );

  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].name, "401772939");
  const data = written[0].data as {
    completed: boolean;
    week: number;
    teams: unknown[];
  };
  assertEquals(data.completed, true);
  assertEquals(data.week, 5);
  assertEquals(data.teams.length, 2);
});

Deno.test("week_stats passes week/seasonType/year through as query params", async () => {
  const { context } = createModelTestContext({
    globalArgs: { userAgent: "nfl-player-stats-test/1.0" },
  });

  let seen: URLSearchParams | undefined;
  await withMockedFetch(
    (req) => {
      const url = new URL(req.url);
      if (url.pathname.endsWith("/scoreboard")) {
        seen = url.searchParams;
        return json({ events: [] });
      }
      return json(summaryFixture());
    },
    () =>
      runWeekStats(
        { week: 5, seasonType: "post", year: 2025 } as unknown as WeekStatsArgs,
        context,
      ),
  );

  assertEquals(seen?.get("week"), "5");
  assertEquals(seen?.get("seasontype"), "3");
  assertEquals(seen?.get("dates"), "2025");
});

Deno.test("week_stats includes unfinished games when includeIncomplete is set", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { userAgent: "nfl-player-stats-test/1.0" },
  });

  await withMockedFetch(
    (req) => {
      const url = new URL(req.url);
      if (url.pathname.endsWith("/scoreboard")) {
        return json({
          events: [
            {
              id: "401772939",
              competitions: [{ status: { type: { completed: false } } }],
            },
          ],
        });
      }
      return json(summaryFixture());
    },
    () =>
      runWeekStats(
        { includeIncomplete: true } as unknown as WeekStatsArgs,
        context,
      ),
  );

  assertEquals(getWrittenResources().length, 1);
});

Deno.test("week_stats throws when every game fails to fetch", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { userAgent: "nfl-player-stats-test/1.0" },
  });

  let threw = false;
  await withMockedFetch(
    (req) => {
      const url = new URL(req.url);
      if (url.pathname.endsWith("/scoreboard")) {
        return json({
          events: [
            {
              id: "401772939",
              competitions: [{ status: { type: { completed: true } } }],
            },
          ],
        });
      }
      return new Response("nope", { status: 500 });
    },
    async () => {
      try {
        await runWeekStats({} as unknown as WeekStatsArgs, context);
      } catch {
        threw = true;
      }
    },
  );

  assertEquals(threw, true);
  assertEquals(getWrittenResources().length, 0);
});
