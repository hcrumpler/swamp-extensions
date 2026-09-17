# @hmcrum/eol-lifecycle

Support/end-of-life lifecycle lookups against the public
[endoflife.date](https://endoflife.date) API.

## Why this exists

"Is this still supported?" is a question with a real, citable answer — a
release date, an end-of-life date, a latest patch version — sitting behind a
free public API. Asking a language model instead produces an impression:
often close, sometimes stale, never citable. This model does the lookup and
hands back the API's own fields plus one computed boolean, `supported`, so
callers don't have to re-derive it from endoflife.date's own quirky
three-state `eol` field (a date, or the literal `true`/`false`) at every call
site.

```
An agent answers:      recalls roughly when a release line ends,
                       states it with confidence
                       -> sometimes right, never citable, drifts over time

This model answers:    fetches the product's cycle list, computes
                       supported = eol date > now
                       -> { cycle: "3.9", eolDate: "2025-10-31",
                            supported: false }
```

## Install

```bash
swamp extension pull @hmcrum/eol-lifecycle
swamp model create @hmcrum/eol-lifecycle eol
```

No configuration is required — the API is public and needs no key.

## Usage

```bash
swamp model method run eol lifecycle --input product=python
swamp model method run eol lifecycle --input product=python --input cycle=3.11
```

| Argument  | Required | Purpose                                                          |
| :-------- | :------- | :---------------------------------------------------------------- |
| `product` | yes      | endoflife.date product identifier, e.g. `python`, `ubuntu`, `postgresql` |
| `cycle`   | no       | Narrow to one release cycle, e.g. `3.11` — omit for every cycle |

## Output

One `lifecycle` resource per call:

- `cycles[]` — per release cycle: `cycle`, `releaseDate`, `eolDate` (the raw
  API field — a date string, or the boolean it can also be), `latest`, and
  the computed `supported` boolean.
- `anyEol` — true if any cycle in `cycles` (i.e. matching `cycle`, when given)
  is past end-of-life.
- `found` / `note` / `suggestions` — see "Unknown products" below.

## Unknown products

A product name endoflife.date doesn't recognize is the single most likely
input, not an exceptional one — this model never throws for it. It returns
`found: false`, an empty `cycles` list, a `note` explaining what happened,
and `suggestions` — close matches pulled live from endoflife.date's own
catalog at `/all.json`, not a hardcoded list:

```json
{
  "product": "pythonn",
  "found": false,
  "cycles": [],
  "note": "endoflife.date has no product \"pythonn\". Close matches: python.",
  "suggestions": ["python"]
}
```

A `cycle` that doesn't exist on an otherwise-valid product degrades the same
way: `found: true`, empty `cycles`, and a `note` listing what cycles actually
exist.

## Design notes

**No product is hardcoded.** The product name is always supplied by the
caller — this model teaches swamp the *shape* of an endoflife.date lookup,
not an opinion about which products matter.

**One fan-out call, not a loop.** A single `lifecycle` call returns every
matching cycle in one resource; nothing about this model requires the caller
to loop per cycle.

**Host-locked.** Every request goes through a `guardedFetch` that refuses any
hostname other than `endoflife.date` — checked before the request and again
after following any redirect — so this model can only ever read the one
source it documents.

## Limitations

- endoflife.date is a community-maintained dataset, not an authoritative
  vendor feed. Treat `eolDate` as a strong signal, not a legal guarantee.
- `latest` reflects whatever endoflife.date's own scrapers most recently
  observed; it can lag a vendor's true latest release by hours to days.

## Development

```bash
~/.swamp/deno/deno check extensions/models/eol_lifecycle.ts
~/.swamp/deno/deno test  extensions/models/eol_lifecycle_test.ts
```

Every test fixture (`widget`, `gadget`, ...) is invented — this model reads a
public API with no infrastructure data to protect, but the fixtures stay
generic anyway so the tests document the *shape* of the API, not a snapshot
of any particular real product's lifecycle.

## License

Apache-2.0. See [LICENSE.md](LICENSE.md).
