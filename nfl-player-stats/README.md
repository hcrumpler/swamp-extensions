# @hmcrum/nfl-player-stats

Real NFL player box-score statistics from ESPN's public, unauthenticated
`summary` endpoint — the missing middle layer between the games, the injuries,
and the fantasy roster.

- [`@hmcrum/nfl-scores`](https://swamp-club.com) has the **games** (final
  score, status, standings).
- [`@hmcrum/nfl-injuries`](https://swamp-club.com) has **who's hurt**.
- [`@dougschaefer/sleeper`](https://swamp-club.com) has the **fantasy
  rosters**.
- This model has **what each player actually did** — passing yards, carries,
  catches, sacks, field goals.

Methods:

- **`box_score`** — given one ESPN `event` id, fan out one resource per team,
  each holding every player's stat line grouped by category (passing, rushing,
  receiving, fumbles, defensive, interceptions, kick/punt returns, kicking,
  punting).
- **`week_stats`** — given a week (or the current week), resolve the scoreboard
  to its games and fetch each one's box score, emitting one resource per game
  with both teams' player lines. Saves you from hunting event ids by hand.
  Fetches only completed games unless `includeIncomplete=true`.

## Installation

```sh
swamp extension pull @hmcrum/nfl-player-stats
```

## Usage

```sh
swamp model create @hmcrum/nfl-player-stats nfl-stats

# Current week's completed games, one resource per game:
swamp model method run nfl-stats week_stats

# A specific past week:
swamp model method run nfl-stats week_stats \
  --input week=5 --input seasonType=regular --input year=2025

# A single game by ESPN event id (e.g. from nfl-scores `scoreboard`):
swamp model method run nfl-stats box_score --input event=401772939

# Read it back:
swamp data get nfl-stats gameStats --json
```

## How it works

Both methods read only `site.api.espn.com`, the same versioned JSON API that
`@hmcrum/nfl-scores` uses — no auth, no secrets, no API key. Every request goes
through a `guardedFetch` that refuses any hostname outside the allowlist, both
before the request and again after any redirect, so a 302 can't walk the run
onto another host. Requests retry 429/5xx with exponential backoff and honour
`Retry-After` — ESPN's public endpoints are someone else's free server.

ESPN encodes each stat category as three parallel arrays: `labels` (what you
read, `"YDS"`), `keys` (what you query, `"passingYards"`), and each athlete's
positional `stats` (`"342"`). This model zips them back together into named
`{ key, label, value }` triples so a consumer never has to track positional
indexes — `category.players[0].stats` is self-describing.

`week_stats` degrades rather than failing whole: a single game that errors or
returns an empty box score is logged and skipped, and the rest of the week
still writes. It only throws if *every* game in the week failed, so a partial
week can never be mistaken for a complete one.

Values are kept as the strings ESPN sends (`"33/49"`, `"1-9"`, `"342"`) rather
than coerced to numbers — many NFL stat cells are genuinely compound
(completions/attempts, sacks-yardsLost) and lossily parsing them would be
worse than handing back exactly what the box score shows.

## License

Apache 2.0 — see LICENSE.md for details.
