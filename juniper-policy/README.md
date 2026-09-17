# @hmcrum/juniper-policy

Deterministic queries over a Junos SRX security policy tree expressed as YAML.

## Why this exists

Ask a language model "is this flow already permitted?" and you get an
impression: sometimes right, never citable, different on the next run. The same
question is really set membership over five dimensions — from-zone, to-zone,
source, destination, application — plus CIDR and port containment.

```
An agent answers:      reads some policy files, forms an impression,
                       writes "no duplicate found"
                       -> sometimes wrong, and always unfalsifiable

This model answers:    parses every policy file, builds the resolved
                       tuple space, does set membership
                       -> { duplicateStatus: "subsumed",
                            matchedPolicy: "common-diagnostics",
                            matchedFile: "_common.yml",
                            matchedLine: 17 }
```

That difference has teeth. A missed duplicate ships a redundant rule into a
config that already holds thousands. A hallucinated duplicate refuses a rule
someone actually needs. Neither failure announces itself.

## Install

```bash
swamp extension pull @hmcrum/juniper-policy
```

## Configure

```bash
swamp model create @hmcrum/juniper-policy srx \
  --global-arg policyDir=/path/to/terraform/security-policies \
  --global-arg terraformMain=/path/to/terraform/main.tf
```

| Global argument | Required | Purpose |
|:--|:--|:--|
| `policyDir` | yes | Directory holding the policy YAML files |
| `terraformMain` | no | Terraform `main.tf`, to learn which role loads which policy file. Omit to skip the unreferenced-file check |
| `untrustedZones` | no | Zones outside the trust boundary. Defaults to `["untrust"]`, the only name Junos itself blesses |
| `trustRank` | no | Zone name to trust rank, higher being more trusted. **No defaults are shipped** — see below |
| `externalAddressPatterns` | no | Extra regexes for names defined outside the YAML tree |

## Expected YAML shape

Each file may hold any of these top-level keys:

```yaml
policy:
  - name: example-permit-web
    match_from_zone: [trust]
    match_to_zone: [dmz]
    match_source_address: [net.example.clients]
    match_destination_address: [net.example.servers]
    match_application: [app-https]
    then: permit
    log_init: true

network_address:
  - name: net.example.clients
    value: 192.0.2.0/24

dns_name:
  - name: service.example.test
    value: service.example.test

address_set:
  - name: set.example.pair
    address: [net.example.clients, net.example.servers]

application:
  - name: app-https
    protocol: tcp
    destination_port: 443

application_set:
  - name: set-web
    applications: [app-https]
```

## Methods

### `load_policies`

Parses the tree once into a typed snapshot. Everything else reads it.

Beyond the obvious inventory, it reports three things the YAML cannot show you:

- **`unreferencedFiles`** — policy files no terraform role loads. The file looks
  live and is applied to nothing.
- **`danglingAddressRefs`** / **`danglingApplicationRefs`** — names a rule uses
  that nothing defines.
- **`duplicateDefinitions`** — names defined in two files, where last-write-wins
  silently.

### `find_duplicates`

Returns `exact`, `subsumed`, `overlapping` or `none` — never a boolean, because
"already covered by a broader rule, close the ticket" and "partly allowed, and
the remainder is the actual request" are different answers.

Normalizes across CIDR containment (v4 and v6, including `::` elision and
IPv4-mapped tails), nested `address_set` membership, `application_set`
expansion, port-range containment, and zone-list supersets. Deny rules never
count as a duplicate.

### `zone_traversal`

Resolves the flow's zone pairs, reports which trust boundaries it crosses, lists
the rules that already exist for those pairs, and emits a mermaid graph built
from parsed data rather than from someone's reading of it.

### `evaluate_checklist`

Answers the mechanical review items with a verdict and `file:line` evidence:
duplicate status, zone traversal, address resolution, application resolution,
address scope, application scope, naming convention, name collision.

Items that need judgment — business justification, exploit scenario, least
privilege, lifecycle — return `requires_human`.

That abstention is the design, not a shortfall. An honest "a person needs to
answer this" routes the question to someone who can; a confident wrong answer
does not.

## Two deliberate refusals

**No default zone taxonomy or trust ordering.** Zone names are an estate's own
vocabulary. A shipped ranking would be one site's segmentation published as
though it were a standard — wrong for every other reader. So `trustRank` starts
empty, and an unranked pair is reported in `unrankedPairs` with
`trustRanked: false`. When that list is non-empty, `lowersTrust: false` means
*not known*, not *safe*. Configure `trustRank` to get a real answer.

**Names defined outside the tree are not called broken.** `any`, `any-ipv6` and
`feed_`-prefixed entries never appear in policy YAML, and neither do names a
rendering layer injects per device. Those land in `externalAddressRefs`, not
`danglingAddressRefs`. Add your own prefixes via `externalAddressPatterns`. A
check that reports fifty findings where forty-nine are fine buries the one real
typo.

## Limitations

- Junos `junos-*` built-in applications are opaque here and compare by name
  only. The device defines them; this tree does not.
- Hostname address objects compare by name, not by resolution. No DNS lookups
  are performed — a resolver answer would make the result non-reproducible.
- `terraformMain` parsing is a brace-counting scan for a map of string lists,
  not a full HCL parse. It degrades to an empty map rather than failing.
- The rule-shadowing case (a rule made dead by an earlier broader permit) is
  reported only as far as `find_duplicates` covers it; there is no whole-tree
  shadow report yet.

## Development

```bash
~/.swamp/deno/deno check  extensions/models/juniper_policy.ts
~/.swamp/deno/deno test   extensions/models/juniper_policy_test.ts
```

Every test fixture is invented. Reserved documentation ranges only
(RFC 5737, RFC 3849, RFC 6761). Publishing a test suite that documents a live
firewall posture would be a disclosure, not a test — if you contribute, keep it
that way.

The load-bearing test is `matches a rule against itself`: hand every permit rule
its own definition back and it must find itself `exact`. A parser that cannot
match a rule to itself will not match anything else either, so that one
assertion catches most normalization bugs for almost no effort.

## License

Apache-2.0. See [LICENSE.md](LICENSE.md).
