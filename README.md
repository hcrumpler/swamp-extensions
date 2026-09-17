# swamp-extensions

Extensions for [swamp](https://github.com/swamp-club/swamp), published to
[swamp-club.com](https://swamp-club.com) under the `@hmcrum` collective.

## Extensions

| Extension | What it teaches swamp | Docs |
|:--|:--|:--|
| [`@hmcrum/juniper-policy`](juniper-policy/) | Deterministic queries over a Junos SRX security policy tree in YAML — duplicate detection, zone traversal, mechanical review checks, each citing file and line | [README](juniper-policy/README.md) |

## Layout

One directory per extension, each self-contained:

```
<extension-name>/
  manifest.yaml     # paths.base: manifest — code resolves from this directory
  <model>.ts        # the model
  <model>_test.ts   # tests, run with the bundled deno
  README.md         # shipped in the published archive
  LICENSE.md        # shipped in the published archive
```

## Working on an extension

The deno that swamp bundles is not on `PATH`:

```bash
~/.swamp/deno/deno check juniper-policy/juniper_policy.ts
~/.swamp/deno/deno test  juniper-policy/juniper_policy_test.ts
```

Use an extension locally, before publishing:

```bash
swamp extension source add /path/to/swamp-extensions
swamp model type search juniper
```

Publish:

```bash
swamp extension fmt     juniper-policy/manifest.yaml
swamp extension quality juniper-policy/manifest.yaml --json
swamp extension push    juniper-policy/manifest.yaml --dry-run
swamp extension push    juniper-policy/manifest.yaml
```

## Contributing

Two rules, both non-negotiable.

**Pin every dependency.** Swamp's bundler inlines npm packages into the
extension bundle, so `deno.lock` does not cover them. Always use an explicit
version in the specifier — `npm:zod@4`, never a bare `zod`. The registry's
scorer runs `deno doc --lint` in a hermetic sandbox with no imports map, so a
bare specifier resolves on your machine and fails at score time.

**Never commit real infrastructure data.** These extensions parse production
network and security configuration. Test fixtures must be invented, using
reserved documentation ranges only:

| Purpose | Use |
|:--|:--|
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) |
| IPv6 | `2001:db8::/32` (RFC 3849) |
| Hostnames | `*.example`, `*.test`, `*.invalid` (RFC 6761) |

That extends past the obvious. Real security zone names, trust orderings,
address-object naming schemes, policy names and internal hostnames are all
reconnaissance material — a zone taxonomy tells a reader how a network is
segmented. Keep site-specific vocabulary in configuration, not in defaults:
if an extension needs a trust ranking or a naming convention, take it as a
global argument rather than shipping one estate's as a built-in.

## License

Apache-2.0. See [LICENSE.md](LICENSE.md).
