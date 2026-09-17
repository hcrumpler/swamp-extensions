/**
 * Model: @hmcrum/juniper-policy — deterministic queries over a Junos SRX
 * security policy tree expressed as YAML.
 *
 * The point of this type is falsifiability. Asking a language model "is this
 * flow already permitted?" produces an impression: sometimes right, never
 * citable, different on the next run. The same question is really set
 * membership over five dimensions (from-zone, to-zone, source, destination,
 * application) plus CIDR and port containment. Set membership has one answer,
 * it can cite the file and line it came from, and it can be unit tested.
 *
 * That distinction has teeth. A missed duplicate ships a redundant rule into a
 * config that already holds thousands. A hallucinated duplicate refuses a rule
 * someone actually needs. Neither failure announces itself.
 *
 * Four methods:
 *
 *   load_policies      parse the tree once into a typed snapshot
 *   find_duplicates    does an existing rule already permit a proposed flow?
 *   zone_traversal     which trust boundaries does a flow cross?
 *   evaluate_checklist mechanical review items, with evidence
 *
 * `evaluate_checklist` deliberately returns `requires_human` for items that
 * need judgment rather than guessing at them. An honest abstention routes the
 * question to someone who can answer it; a confident wrong answer does not.
 *
 * Everything is read-only. This model parses files and never writes to a
 * device or a repo.
 *
 * @module
 */
import { z } from "npm:zod@4";
import { parse as parseYaml } from "jsr:@std/yaml@1.0.5";

// ---------------------------------------------------------------------------
// Address arithmetic
//
// Junos address books mix IPv4 CIDRs, IPv6 CIDRs, bare hostnames and named
// sets. Containment is the only honest way to compare them, so both families
// are normalized to (BigInt network, prefix length, bit width).
// ---------------------------------------------------------------------------

interface Cidr {
  /** Network address with host bits cleared. */
  network: bigint;
  prefix: number;
  /** 32 for IPv4, 128 for IPv6 — also the family discriminator. */
  bits: 32 | 128;
}

/** Parse dotted-quad IPv4 into a BigInt, or null if it is not one. */
function parseIpv4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

/** Parse IPv6 including `::` elision and IPv4-mapped tails, or null. */
function parseIpv6(text: string): bigint | null {
  if (!text.includes(":")) return null;

  let head = text;
  let tail = "";
  const elision = text.indexOf("::");
  if (elision !== -1) {
    if (text.indexOf("::", elision + 1) !== -1) return null; // only one `::`
    head = text.slice(0, elision);
    tail = text.slice(elision + 2);
  }

  const expand = (segment: string): string[] | null => {
    if (segment === "") return [];
    const groups: string[] = [];
    for (const raw of segment.split(":")) {
      if (raw.includes(".")) {
        // IPv4-mapped tail: fold into two 16-bit groups.
        const v4 = parseIpv4(raw);
        if (v4 === null) return null;
        groups.push(((v4 >> 16n) & 0xffffn).toString(16));
        groups.push((v4 & 0xffffn).toString(16));
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(raw)) return null;
      groups.push(raw);
    }
    return groups;
  };

  const headGroups = expand(head);
  const tailGroups = expand(tail);
  if (headGroups === null || tailGroups === null) return null;

  const missing = 8 - headGroups.length - tailGroups.length;
  if (elision === -1) {
    if (headGroups.length !== 8) return null;
  } else if (missing < 0) return null;

  const groups = elision === -1
    ? headGroups
    : [...headGroups, ...Array(missing).fill("0"), ...tailGroups];

  let value = 0n;
  for (const group of groups) {
    value = (value << 16n) | BigInt(parseInt(group, 16));
  }
  return value;
}

/**
 * Parse `10.0.0.0/8`, `10.0.0.1`, `2001:db8::/32` into a Cidr. A bare address
 * is treated as a host route (/32 or /128), which is how the address book means
 * it. Returns null for hostnames and anything unparseable — callers fall back
 * to name comparison for those.
 */
export function parseCidr(text: string): Cidr | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;

  const slash = trimmed.lastIndexOf("/");
  const addressPart = slash === -1 ? trimmed : trimmed.slice(0, slash);
  const prefixPart = slash === -1 ? null : trimmed.slice(slash + 1);

  const v4 = parseIpv4(addressPart);
  const v6 = v4 === null ? parseIpv6(addressPart) : null;
  if (v4 === null && v6 === null) return null;

  const bits: 32 | 128 = v4 !== null ? 32 : 128;
  let prefix: number = bits;
  if (prefixPart !== null) {
    if (!/^\d{1,3}$/.test(prefixPart)) return null;
    prefix = Number(prefixPart);
    if (prefix > bits) return null;
  }

  const raw = v4 !== null ? v4 : (v6 as bigint);
  const hostBits = BigInt(bits - prefix);
  const network = hostBits === 0n ? raw : (raw >> hostBits) << hostBits;
  return { network, prefix, bits };
}

/** True when every address in `inner` is also in `outer`. */
export function cidrContains(outer: Cidr, inner: Cidr): boolean {
  if (outer.bits !== inner.bits) return false;
  if (outer.prefix > inner.prefix) return false;
  const hostBits = BigInt(inner.bits - outer.prefix);
  const innerNetwork = hostBits === 0n
    ? inner.network
    : (inner.network >> hostBits) << hostBits;
  return innerNetwork === outer.network;
}

// ---------------------------------------------------------------------------
// Port arithmetic
// ---------------------------------------------------------------------------

interface PortRange {
  low: number;
  high: number;
}

/** Parse `443`, `8000-8100`, or `1-65535`. Returns null if unparseable. */
export function parsePortRange(text: string | number): PortRange | null {
  const raw = String(text).trim();
  if (raw === "") return null;
  const dash = raw.indexOf("-");
  if (dash === -1) {
    if (!/^\d{1,5}$/.test(raw)) return null;
    const port = Number(raw);
    return port <= 65535 ? { low: port, high: port } : null;
  }
  const low = raw.slice(0, dash);
  const high = raw.slice(dash + 1);
  if (!/^\d{1,5}$/.test(low) || !/^\d{1,5}$/.test(high)) return null;
  const lowPort = Number(low);
  const highPort = Number(high);
  if (lowPort > 65535 || highPort > 65535 || lowPort > highPort) return null;
  return { low: lowPort, high: highPort };
}

const portContains = (outer: PortRange, inner: PortRange): boolean =>
  outer.low <= inner.low && outer.high >= inner.high;

// ---------------------------------------------------------------------------
// Parsed shapes
// ---------------------------------------------------------------------------

const PolicyRuleSchema = z.object({
  name: z.string(),
  /** Basename of the YAML file the rule came from — half of every citation. */
  file: z.string(),
  /** 1-based line of the rule's `- name:` key. The other half. */
  line: z.number(),
  /** Zero-based index within the file, which is Junos evaluation order. */
  ordinal: z.number(),
  fromZones: z.array(z.string()),
  toZones: z.array(z.string()),
  sourceAddresses: z.array(z.string()),
  destinationAddresses: z.array(z.string()),
  applications: z.array(z.string()),
  /** permit, deny or reject. */
  action: z.string(),
  logInit: z.boolean(),
  idpPolicies: z.array(z.string()),
});

type PolicyRule = z.infer<typeof PolicyRuleSchema>;

const AddressObjectSchema = z.object({
  name: z.string(),
  /** network_address, dns_name or address_set. */
  kind: z.string(),
  /** CIDR or hostname for leaves; empty for sets. */
  value: z.string(),
  /** Direct members for address_set; empty for leaves. */
  members: z.array(z.string()),
  file: z.string(),
  line: z.number(),
});

type AddressObject = z.infer<typeof AddressObjectSchema>;

const ApplicationObjectSchema = z.object({
  name: z.string(),
  /** application or application_set. */
  kind: z.string(),
  protocol: z.string(),
  destinationPort: z.string(),
  members: z.array(z.string()),
  file: z.string(),
  line: z.number(),
});

type ApplicationObject = z.infer<typeof ApplicationObjectSchema>;

const SnapshotSchema = z.object({
  policyDir: z.string(),
  fileCount: z.number(),
  files: z.array(z.string()),
  policies: z.array(PolicyRuleSchema),
  policyCount: z.number(),
  addresses: z.array(AddressObjectSchema),
  addressCount: z.number(),
  applications: z.array(ApplicationObjectSchema),
  applicationCount: z.number(),
  /** Every zone name any rule mentions, sorted. */
  zones: z.array(z.string()),
  /** Terraform role → policy files it loads, from the `locals.policies` map. */
  rolesToFiles: z.record(z.string(), z.array(z.string())),
  /**
   * Policy files no terraform role loads. Invisible in the YAML itself: the
   * file looks live, and is applied to nothing.
   */
  unreferencedFiles: z.array(z.string()),
  /** Names used by a rule that no address or application object defines. */
  danglingAddressRefs: z.array(z.string()),
  danglingApplicationRefs: z.array(z.string()),
  /**
   * Names that resolve outside this YAML tree and so cannot be checked here:
   * Junos built-ins, dynamic address feeds, and anything the rendering layer
   * injects per device. Kept separate from `danglingAddressRefs` on purpose —
   * folding them together would bury the handful of real typos in a pile of
   * names that are perfectly fine.
   */
  externalAddressRefs: z.array(z.string()),
  /** Names defined more than once, where last-write-wins silently. */
  duplicateDefinitions: z.array(z.string()),
  parseErrors: z.array(z.object({ file: z.string(), error: z.string() })),
  fetchedAt: z.string(),
});

type Snapshot = z.infer<typeof SnapshotSchema>;

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/** Narrow an untyped YAML value for field access. */
// deno-lint-ignore no-explicit-any
const asAny = (v: unknown): any => v;

function str(v: unknown, fallback = ""): string {
  return v === null || v === undefined ? fallback : String(v);
}

/** Coerce a YAML scalar-or-sequence into a string array. */
function strList(v: unknown): string[] {
  if (v === null || v === undefined) return [];
  if (Array.isArray(v)) {
    return v.map((item) => str(item).trim()).filter(Boolean);
  }
  const single = str(v).trim();
  return single === "" ? [] : [single];
}

/**
 * Line number of the nth `- name: <value>` occurrence in `text`.
 *
 * @std/yaml discards source positions, and a citation without a line is a
 * citation nobody can check, so the raw text is scanned once per file and the
 * offsets are zipped back onto the parsed nodes by name.
 */
function nameLineIndex(text: string): Map<string, number[]> {
  const index = new Map<string, number[]>();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const match = /^\s*-\s+name:\s*(.+?)\s*(?:#.*)?$/.exec(lines[i]);
    if (match === null) continue;
    const name = match[1].replace(/^["']|["']$/g, "");
    const seen = index.get(name);
    if (seen === undefined) index.set(name, [i + 1]);
    else seen.push(i + 1);
  }
  return index;
}

/** Pop the next known line for `name`, so repeats map to distinct lines. */
function takeLine(index: Map<string, number[]>, name: string): number {
  const lines = index.get(name);
  if (lines === undefined || lines.length === 0) return 0;
  return lines.shift() as number;
}

/**
 * Parse `locals.policies` out of terraform main.tf: role name → the policy
 * files it loads. A brace-counting scan rather than a real HCL parse, which is
 * enough for a map of string lists and degrades to `{}` on anything else.
 */
export function parseRolesToFiles(mainTf: string): Record<string, string[]> {
  const roles: Record<string, string[]> = {};
  let currentRole: string | null = null;
  for (const line of mainTf.split("\n")) {
    const roleStart = /^\s*([A-Za-z0-9_-]+)\s*=\s*\[/.exec(line);
    if (roleStart !== null) {
      currentRole = roleStart[1];
      roles[currentRole] = [];
      continue;
    }
    if (currentRole !== null && /^\s*\]/.test(line)) {
      currentRole = null;
      continue;
    }
    if (currentRole === null) continue;
    const fileRef = /"[^"]*security-policies\/([^"/]+\.ya?ml)"/.exec(line);
    if (fileRef !== null) roles[currentRole].push(fileRef[1]);
  }
  // main.tf holds plenty of other string lists — depends_on, interface flags.
  // A list with no policy files in it is not a role, so drop it rather than
  // reporting an empty role that never existed.
  for (const [role, files] of Object.entries(roles)) {
    if (files.length === 0) delete roles[role];
  }
  return roles;
}

interface ParsedFile {
  policies: PolicyRule[];
  addresses: AddressObject[];
  applications: ApplicationObject[];
}

/** Parse one policy YAML document into typed nodes. Throws on invalid YAML. */
export function parsePolicyFile(file: string, text: string): ParsedFile {
  const doc = asAny(parseYaml(text));
  const lineIndex = nameLineIndex(text);
  const out: ParsedFile = { policies: [], addresses: [], applications: [] };
  if (doc === null || typeof doc !== "object") return out;

  let ordinal = 0;
  for (const raw of (Array.isArray(doc.policy) ? doc.policy : [])) {
    const node = asAny(raw);
    const name = str(node?.name);
    if (name === "") continue;
    const idpPolicies: string[] = [];
    for (
      const svc of (Array.isArray(node.permit_application_services)
        ? node.permit_application_services
        : [])
    ) {
      const idp = str(asAny(svc)?.idp_policy);
      if (idp !== "") {
        idpPolicies.push(idp);
      }
    }
    out.policies.push({
      name,
      file,
      line: takeLine(lineIndex, name),
      ordinal: ordinal++,
      fromZones: strList(node.match_from_zone),
      toZones: strList(node.match_to_zone),
      sourceAddresses: strList(node.match_source_address),
      destinationAddresses: strList(node.match_destination_address),
      applications: strList(node.match_application),
      action: str(node.then, "permit"),
      logInit: node.log_init === true,
      idpPolicies,
    });
  }

  for (
    const [key, kind] of [
      ["network_address", "network_address"],
      ["dns_name", "dns_name"],
    ] as const
  ) {
    for (const raw of (Array.isArray(doc[key]) ? doc[key] : [])) {
      const node = asAny(raw);
      const name = str(node?.name);
      if (name === "") continue;
      out.addresses.push({
        name,
        kind,
        value: str(node.value, name),
        members: [],
        file,
        line: takeLine(lineIndex, name),
      });
    }
  }

  for (const raw of (Array.isArray(doc.address_set) ? doc.address_set : [])) {
    const node = asAny(raw);
    const name = str(node?.name);
    if (name === "") continue;
    out.addresses.push({
      name,
      kind: "address_set",
      value: "",
      // Junos allows both `address` and `address_set` members.
      members: [...strList(node.address), ...strList(node.address_set)],
      file,
      line: takeLine(lineIndex, name),
    });
  }

  for (const raw of (Array.isArray(doc.application) ? doc.application : [])) {
    const node = asAny(raw);
    const name = str(node?.name);
    if (name === "") continue;
    out.applications.push({
      name,
      kind: "application",
      protocol: str(node.protocol).toLowerCase(),
      destinationPort: str(node.destination_port),
      members: [],
      file,
      line: takeLine(lineIndex, name),
    });
  }

  for (
    const raw of (Array.isArray(doc.application_set) ? doc.application_set : [])
  ) {
    const node = asAny(raw);
    const name = str(node?.name);
    if (name === "") continue;
    out.applications.push({
      name,
      kind: "application_set",
      protocol: "",
      destinationPort: "",
      members: [
        ...strList(node.applications),
        ...strList(node.application),
        ...strList(node.application_set),
      ],
      file,
      line: takeLine(lineIndex, name),
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// Resolution
//
// The comparison itself is easy. Normalizing the two sides so a comparison
// means anything is the actual work, and it is where a parser earns its keep
// over an impression: a `/32` host route sitting inside a `/21` the address
// book names, a member reached through two levels of address_set, port 8050
// inside a declared 8000-8100 range.
// ---------------------------------------------------------------------------

/** A leaf address: a CIDR, or a hostname when it is not numeric. */
interface Leaf {
  name: string;
  cidr: Cidr | null;
  hostname: string;
}

class Resolver {
  private readonly addresses = new Map<string, AddressObject>();
  private readonly applications = new Map<string, ApplicationObject>();

  constructor(addresses: AddressObject[], applications: ApplicationObject[]) {
    for (const a of addresses) {
      if (!this.addresses.has(a.name)) this.addresses.set(a.name, a);
    }
    for (const a of applications) {
      if (!this.applications.has(a.name)) this.applications.set(a.name, a);
    }
  }

  /** Flatten an address name to leaves, following sets. Cycle-safe. */
  addressLeaves(name: string, seen = new Set<string>()): Leaf[] {
    const trimmed = name.trim();
    if (trimmed === "" || seen.has(trimmed)) return [];
    seen.add(trimmed);

    const object = this.addresses.get(trimmed);
    if (object === undefined) {
      // Unknown name. It may still be a literal CIDR written inline.
      const cidr = parseCidr(trimmed);
      return [{ name: trimmed, cidr, hostname: cidr === null ? trimmed : "" }];
    }
    if (object.kind === "address_set") {
      return object.members.flatMap((m) => this.addressLeaves(m, seen));
    }
    const cidr = parseCidr(object.value);
    return [{
      name: object.name,
      cidr,
      hostname: cidr === null ? object.value.toLowerCase() : "",
    }];
  }

  /** Flatten an application name to (protocol, port range) leaves. */
  applicationLeaves(
    name: string,
    seen = new Set<string>(),
  ): Array<{ name: string; protocol: string; ports: PortRange | null }> {
    const trimmed = name.trim();
    if (trimmed === "" || seen.has(trimmed)) return [];
    seen.add(trimmed);

    const object = this.applications.get(trimmed);
    if (object === undefined) {
      // Junos ships hundreds of junos-* built-ins this repo never redefines.
      // They are opaque here, so they compare by name only.
      return [{ name: trimmed, protocol: "", ports: null }];
    }
    if (object.kind === "application_set") {
      return object.members.flatMap((m) => this.applicationLeaves(m, seen));
    }
    return [{
      name: object.name,
      protocol: object.protocol,
      ports: parsePortRange(object.destinationPort),
    }];
  }

  hasAddress(name: string): boolean {
    return this.addresses.has(name.trim());
  }

  hasApplication(name: string): boolean {
    return this.applications.has(name.trim());
  }
}

const isAny = (values: string[]): boolean =>
  values.some((v) => v.trim().toLowerCase() === "any");

/** True when `outer` (an existing rule's set) covers `inner` (the proposal). */
function addressCovers(
  resolver: Resolver,
  outer: string[],
  inner: string[],
): boolean {
  if (isAny(outer)) return true;
  if (isAny(inner)) return false; // only `any` covers `any`
  const outerLeaves = outer.flatMap((n) => resolver.addressLeaves(n));
  return inner.every((name) =>
    resolver.addressLeaves(name).every((needle) =>
      outerLeaves.some((hay) => {
        if (needle.cidr !== null && hay.cidr !== null) {
          return cidrContains(hay.cidr, needle.cidr);
        }
        if (needle.hostname !== "" && hay.hostname !== "") {
          return needle.hostname === hay.hostname;
        }
        return needle.name === hay.name;
      })
    )
  );
}

function applicationCovers(
  resolver: Resolver,
  outer: string[],
  inner: string[],
): boolean {
  if (isAny(outer)) return true;
  if (isAny(inner)) return false;
  const outerLeaves = outer.flatMap((n) => resolver.applicationLeaves(n));
  return inner.every((name) =>
    resolver.applicationLeaves(name).every((needle) =>
      outerLeaves.some((hay) => {
        if (needle.name === hay.name) return true;
        if (
          needle.protocol !== "" && needle.protocol === hay.protocol &&
          needle.ports !== null && hay.ports !== null
        ) {
          return portContains(hay.ports, needle.ports);
        }
        return false;
      })
    )
  );
}

const zoneCovers = (outer: string[], inner: string[]): boolean =>
  isAny(outer) || inner.every((z) => outer.includes(z));

const sameSet = (a: string[], b: string[]): boolean =>
  a.length === b.length &&
  [...a].sort().join("\u0000") === [...b].sort().join("\u0000");

// ---------------------------------------------------------------------------
// Method output shapes
// ---------------------------------------------------------------------------

const ProposalSchema = z.object({
  fromZone: z.array(z.string()).min(1).describe(
    "Source security zone(s) of the proposed flow",
  ),
  toZone: z.array(z.string()).min(1).describe(
    "Destination security zone(s) of the proposed flow",
  ),
  sourceAddress: z.array(z.string()).min(1).describe(
    "Source address book names, literal CIDRs, or `any`",
  ),
  destinationAddress: z.array(z.string()).min(1).describe(
    "Destination address book names, literal CIDRs, or `any`",
  ),
  application: z.array(z.string()).min(1).describe(
    "Application or application-set names, or `any`",
  ),
});

/** How an existing rule relates to a proposal. */
const RelationSchema = z.enum(["exact", "subsumed", "overlapping"]);

/** Adds the "nothing covers it" case that only a whole result can carry. */
const DuplicateStatusSchema = z.enum([
  "exact",
  "subsumed",
  "overlapping",
  "none",
]);

const MatchSchema = z.object({
  policy: z.string(),
  file: z.string(),
  line: z.number(),
  relation: RelationSchema,
  action: z.string(),
  /** Which of the five dimensions the existing rule fully covers. */
  covers: z.object({
    fromZone: z.boolean(),
    toZone: z.boolean(),
    source: z.boolean(),
    destination: z.boolean(),
    application: z.boolean(),
  }),
  citation: z.string(),
});

const DuplicateResultSchema = z.object({
  proposal: ProposalSchema,
  /** Never a boolean: the four cases lead to four different decisions. */
  duplicateStatus: DuplicateStatusSchema,
  matches: z.array(MatchSchema),
  matchCount: z.number(),
  /** The single strongest match, or empty when status is `none`. */
  matchedPolicy: z.string(),
  matchedFile: z.string(),
  matchedLine: z.number(),
  /** Proposal names that no address or application object defines. */
  unknownReferences: z.array(z.string()),
  policiesConsidered: z.number(),
  explanation: z.string(),
  fetchedAt: z.string(),
});

const ZoneTraversalSchema = z.object({
  fromZones: z.array(z.string()),
  toZones: z.array(z.string()),
  /** Every from→to pair the flow implies. */
  pairs: z.array(z.object({
    fromZone: z.string(),
    toZone: z.string(),
    intraZone: z.boolean(),
    crossesUntrust: z.boolean(),
    /** False when either zone has no configured trust rank. */
    trustRanked: z.boolean(),
    /** Meaningless unless `trustRanked` — do not read it on its own. */
    trustDelta: z.number(),
  })),
  crossesUntrust: z.boolean(),
  /** True when any ranked pair leaves a zone for a less trusted one. */
  lowersTrust: z.boolean(),
  /**
   * Pairs whose trust could not be compared because no rank was configured.
   * A non-empty list means `lowersTrust: false` is "not known", not "safe".
   */
  unrankedPairs: z.array(z.string()),
  unknownZones: z.array(z.string()),
  /** Rules already present for these zone pairs — the review's starting set. */
  existingRuleCount: z.number(),
  existingRules: z.array(z.string()),
  mermaid: z.string(),
  fetchedAt: z.string(),
});

const ChecklistItemSchema = z.object({
  id: z.number(),
  item: z.string(),
  verdict: z.enum(["pass", "fail", "requires_human"]),
  detail: z.string(),
  /** file:line citations, empty when there is nothing to cite. */
  evidence: z.array(z.string()),
});

const ChecklistSchema = z.object({
  proposal: ProposalSchema,
  policyName: z.string(),
  items: z.array(ChecklistItemSchema),
  passed: z.number(),
  failed: z.number(),
  requiresHuman: z.number(),
  /** True when nothing mechanical failed. Not "approved". */
  mechanicallyClear: z.boolean(),
  fetchedAt: z.string(),
});

// ---------------------------------------------------------------------------
// Zone trust ordering
//
// There is deliberately no default ranking. Zone names are an estate's own
// vocabulary, and a shipped table would be one site's topology published as
// though it were a standard — wrong for every other reader, and a disclosure
// for the one it came from. `untrust` is the only name Junos itself blesses.
//
// With no ranking configured, trust comparisons report `unranked` rather than
// a reassuring zero. A silent "no trust drop detected" from a table that
// contains neither zone is the exact failure this model exists to prevent.
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  policyDir: z.string().describe(
    "Directory holding the security policy YAML files, e.g. /path/to/terraform/security-policies",
  ),
  terraformMain: z.string().default("").describe(
    "Optional path to terraform main.tf, to learn which role loads which policy file. Empty skips the unreferenced-file check",
  ),
  untrustedZones: z.array(z.string()).default(["untrust"]).describe(
    "Zones treated as outside the trust boundary. Defaults to the single Junos-conventional name; add your own",
  ),
  trustRank: z.record(z.string(), z.number()).default({}).describe(
    "Zone name to trust rank, higher being more trusted. No defaults are shipped — an assumed trust model that does not match the real one is worse than none, so unranked zones are reported as unranked rather than assumed equal",
  ),
  externalAddressPatterns: z.array(z.string()).default([]).describe(
    "Extra regexes for address names defined outside the YAML tree, such as names a rendering layer injects per device or objects fed in from an inventory system. Matches are reported as external rather than broken",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/**
 * Method context.
 *
 * There is deliberately no `readResource` here. `find_duplicates`,
 * `zone_traversal` and `evaluate_checklist` each re-parse the tree rather than
 * reading the snapshot `load_policies` wrote. Parsing costs about a tenth of a
 * second and a query costs two milliseconds, so the saving would be trivial —
 * and the cost would be answering "is this already permitted?" from a snapshot
 * taken before someone else's merge. A stale `none` is the most dangerous wrong
 * answer this model can give, so freshness wins.
 */
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

/**
 * Make a safe, stable resource name from caller-supplied text.
 *
 * Zone and policy names come from user input and end up as data resource names,
 * so anything outside a conservative set becomes a hyphen.
 */
export function resourceName(parts: string[], fallback: string): string {
  const slug = parts
    .join("-")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .slice(0, 80);
  return slug === "" ? fallback : slug;
}

// ---------------------------------------------------------------------------
// Snapshot assembly
// ---------------------------------------------------------------------------

/**
 * Address names that are real but can never appear in a policy YAML tree.
 *
 * `any` and `any-ipv6` are Junos built-ins. A `feed_`-prefixed name is the
 * common convention for an entry supplied by a dynamic address feed server
 * rather than by configuration. Flagging either as a broken reference would be
 * wrong on every run — and a check that cries wolf dozens of times is a check
 * nobody reads.
 *
 * Estates whose names are rendered per device, or fed in from an inventory
 * system, should add those prefixes via the `externalAddressPatterns` global
 * argument. Such prefixes are deliberately not shipped as defaults: guessing at
 * another estate's naming convention is how false confidence gets built in.
 */
const DEFAULT_EXTERNAL_ADDRESS_PATTERNS: string[] = [
  "^any$",
  "^any-",
  "^feed_",
];

/** Compile patterns, skipping any that are not valid regexes. */
function compilePatterns(patterns: string[]): RegExp[] {
  const out: RegExp[] = [];
  for (const pattern of patterns) {
    try {
      out.push(new RegExp(pattern));
    } catch {
      // An unusable pattern must not take the run down with it.
    }
  }
  return out;
}

/** Build a snapshot from already-read file contents. Pure — hence testable. */
export function buildSnapshot(
  policyDir: string,
  files: Array<{ name: string; text: string }>,
  mainTf: string,
  externalAddressPatterns: string[] = DEFAULT_EXTERNAL_ADDRESS_PATTERNS,
): Snapshot {
  const policies: PolicyRule[] = [];
  const addresses: AddressObject[] = [];
  const applications: ApplicationObject[] = [];
  const parseErrors: Array<{ file: string; error: string }> = [];

  for (
    const { name, text } of [...files].sort((a, b) =>
      a.name.localeCompare(b.name)
    )
  ) {
    try {
      const parsed = parsePolicyFile(name, text);
      policies.push(...parsed.policies);
      addresses.push(...parsed.addresses);
      applications.push(...parsed.applications);
    } catch (error) {
      parseErrors.push({
        file: name,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const zones = [
    ...new Set(policies.flatMap((p) => [...p.fromZones, ...p.toZones])),
  ].filter((z) => z.toLowerCase() !== "any").sort();

  const rolesToFiles = mainTf === "" ? {} : parseRolesToFiles(mainTf);
  const loaded = new Set(Object.values(rolesToFiles).flat());
  const unreferencedFiles = mainTf === ""
    ? []
    : files.map((f) => f.name).filter((f) => !loaded.has(f)).sort();

  const addressNames = new Set(addresses.map((a) => a.name));
  const applicationNames = new Set(applications.map((a) => a.name));

  const referencedAddresses = new Set(
    policies.flatMap((p) => [...p.sourceAddresses, ...p.destinationAddresses]),
  );
  for (const set of addresses.filter((a) => a.kind === "address_set")) {
    for (const m of set.members) referencedAddresses.add(m);
  }
  const referencedApplications = new Set(
    policies.flatMap((p) => p.applications),
  );
  for (const set of applications.filter((a) => a.kind === "application_set")) {
    for (const m of set.members) referencedApplications.add(m);
  }

  const unresolvedAddresses = [...referencedAddresses]
    .filter((n) =>
      n.toLowerCase() !== "any" && !addressNames.has(n) && parseCidr(n) === null
    );
  const externalMatchers = compilePatterns(externalAddressPatterns);
  const isExternalName = (name: string): boolean =>
    externalMatchers.some((re) => re.test(name));

  const danglingAddressRefs = unresolvedAddresses
    .filter((n) => !isExternalName(n))
    .sort();
  const externalAddressRefs = unresolvedAddresses
    .filter((n) => isExternalName(n))
    .sort();
  // junos-* built-ins are defined by the device, not by this repo.
  const danglingApplicationRefs = [...referencedApplications]
    .filter((n) =>
      n.toLowerCase() !== "any" && !applicationNames.has(n) &&
      !n.startsWith("junos-")
    )
    .sort();

  const seen = new Set<string>();
  const duplicateDefinitions: string[] = [];
  for (const name of [...addresses, ...applications].map((o) => o.name)) {
    if (seen.has(name)) duplicateDefinitions.push(name);
    else seen.add(name);
  }

  return {
    policyDir,
    fileCount: files.length,
    files: files.map((f) => f.name).sort(),
    policies,
    policyCount: policies.length,
    addresses,
    addressCount: addresses.length,
    applications,
    applicationCount: applications.length,
    zones,
    rolesToFiles,
    unreferencedFiles,
    danglingAddressRefs,
    externalAddressRefs,
    danglingApplicationRefs,
    duplicateDefinitions: [...new Set(duplicateDefinitions)].sort(),
    parseErrors,
    fetchedAt: new Date().toISOString(),
  };
}

/**
 * Classify a proposal against a snapshot.
 *
 * `exact` means an existing rule matches on all five dimensions. `subsumed`
 * means an existing rule is broader and already permits the whole flow.
 * `overlapping` means an existing rule permits part of it. These lead to
 * different decisions, which is why this is not a boolean: "already covered by
 * a broader rule, close your ticket" and "partly allowed, and the remainder is
 * the actual request" are not the same answer.
 */
export function classifyProposal(
  snapshot: Snapshot,
  proposal: z.infer<typeof ProposalSchema>,
): z.infer<typeof DuplicateResultSchema> {
  const resolver = new Resolver(snapshot.addresses, snapshot.applications);
  const matches: Array<z.infer<typeof MatchSchema>> = [];

  for (const rule of snapshot.policies) {
    if (rule.action !== "permit") continue;

    const covers = {
      fromZone: zoneCovers(rule.fromZones, proposal.fromZone),
      toZone: zoneCovers(rule.toZones, proposal.toZone),
      source: addressCovers(
        resolver,
        rule.sourceAddresses,
        proposal.sourceAddress,
      ),
      destination: addressCovers(
        resolver,
        rule.destinationAddresses,
        proposal.destinationAddress,
      ),
      application: applicationCovers(
        resolver,
        rule.applications,
        proposal.application,
      ),
    };

    // Zones must line up for a rule to be relevant at all.
    if (!covers.fromZone || !covers.toZone) continue;

    const full = covers.source && covers.destination && covers.application;
    const partial = covers.source || covers.destination || covers.application;
    if (!full && !partial) continue;

    const identical = full &&
      sameSet(rule.fromZones, proposal.fromZone) &&
      sameSet(rule.toZones, proposal.toZone) &&
      sameSet(rule.sourceAddresses, proposal.sourceAddress) &&
      sameSet(rule.destinationAddresses, proposal.destinationAddress) &&
      sameSet(rule.applications, proposal.application);

    matches.push({
      policy: rule.name,
      file: rule.file,
      line: rule.line,
      relation: identical ? "exact" : full ? "subsumed" : "overlapping",
      action: rule.action,
      covers,
      citation: `${rule.file}:${rule.line}`,
    });
  }

  const rank: Record<string, number> = {
    exact: 3,
    subsumed: 2,
    overlapping: 1,
  };
  matches.sort((a, b) => rank[b.relation] - rank[a.relation]);

  const strongest = matches[0];
  const duplicateStatus = strongest === undefined ? "none" : strongest.relation;

  const unknownReferences = [
    ...proposal.sourceAddress,
    ...proposal.destinationAddress,
  ].filter((n) =>
    n.toLowerCase() !== "any" && !resolver.hasAddress(n) &&
    parseCidr(n) === null
  ).concat(
    proposal.application.filter((n) =>
      n.toLowerCase() !== "any" && !resolver.hasApplication(n) &&
      !n.startsWith("junos-")
    ),
  );

  const explanation = strongest === undefined
    ? "No existing permit rule covers any part of this flow."
    : strongest.relation === "exact"
    ? `${strongest.policy} (${strongest.citation}) already permits exactly this flow.`
    : strongest.relation === "subsumed"
    ? `${strongest.policy} (${strongest.citation}) is broader and already permits this entire flow.`
    : `${strongest.policy} (${strongest.citation}) permits part of this flow; the remainder is not covered.`;

  return {
    proposal,
    duplicateStatus,
    matches,
    matchCount: matches.length,
    matchedPolicy: strongest?.policy ?? "",
    matchedFile: strongest?.file ?? "",
    matchedLine: strongest?.line ?? 0,
    unknownReferences: [...new Set(unknownReferences)].sort(),
    policiesConsidered: snapshot.policies.filter((p) => p.action === "permit")
      .length,
    explanation,
    fetchedAt: new Date().toISOString(),
  };
}

/** Resolve zone pairs and trust deltas for a flow. Pure. */
export function analyzeTraversal(
  snapshot: Snapshot,
  fromZones: string[],
  toZones: string[],
  untrustedZones: string[],
  trustRank: Record<string, number>,
): z.infer<typeof ZoneTraversalSchema> {
  const ranks: Record<string, number> = { ...trustRank };
  const untrusted = new Set(untrustedZones.map((z) => z.toLowerCase()));
  const known = new Set(snapshot.zones);

  const pairs: z.infer<typeof ZoneTraversalSchema>["pairs"] = [];
  for (const from of fromZones) {
    for (const to of toZones) {
      const fromRank = ranks[from];
      const toRank = ranks[to];
      const ranked = fromRank !== undefined && toRank !== undefined;
      pairs.push({
        fromZone: from,
        toZone: to,
        intraZone: from === to,
        crossesUntrust: untrusted.has(from.toLowerCase()) ||
          untrusted.has(to.toLowerCase()),
        trustRanked: ranked,
        trustDelta: ranked ? toRank - fromRank : 0,
      });
    }
  }

  const existingRules = snapshot.policies
    .filter((p) =>
      p.action === "permit" &&
      zoneCovers(p.fromZones, fromZones) && zoneCovers(p.toZones, toZones)
    )
    .map((p) => `${p.name} (${p.file}:${p.line})`);

  const unknownZones = [...new Set([...fromZones, ...toZones])]
    .filter((z) => z.toLowerCase() !== "any" && !known.has(z))
    .sort();

  const edges = pairs
    .map((p) =>
      `  ${p.fromZone} -->|${
        p.crossesUntrust ? "crosses untrust" : "internal"
      }| ${p.toZone}`
    )
    .join("\n");

  return {
    fromZones,
    toZones,
    pairs,
    crossesUntrust: pairs.some((p) => p.crossesUntrust),
    lowersTrust: pairs.some((p) => p.trustRanked && p.trustDelta < 0),
    unrankedPairs: pairs.filter((p) => !p.trustRanked).map((p) =>
      `${p.fromZone} -> ${p.toZone}`
    ),
    unknownZones,
    existingRuleCount: existingRules.length,
    existingRules,
    mermaid: `graph LR\n${edges}`,
    fetchedAt: new Date().toISOString(),
  };
}

/**
 * Answer the mechanical review items and abstain on the rest.
 *
 * The abstentions are the design, not a shortfall. "Is this application scope
 * defensible for this service?" has no lookup behind it, and a parser that
 * invents an answer is worse than one that says so.
 */
export function evaluateChecklistItems(
  snapshot: Snapshot,
  proposal: z.infer<typeof ProposalSchema>,
  policyName: string,
  untrustedZones: string[],
  trustRank: Record<string, number>,
  namePattern: string,
): z.infer<typeof ChecklistSchema> {
  const duplicate = classifyProposal(snapshot, proposal);
  const traversal = analyzeTraversal(
    snapshot,
    proposal.fromZone,
    proposal.toZone,
    untrustedZones,
    trustRank,
  );
  const resolver = new Resolver(snapshot.addresses, snapshot.applications);

  const items: Array<z.infer<typeof ChecklistItemSchema>> = [];
  type Verdict = z.infer<typeof ChecklistItemSchema>["verdict"];
  const add = (
    id: number,
    item: string,
    verdict: Verdict,
    detail: string,
    evidence: string[] = [],
  ) => items.push({ id, item, verdict, detail, evidence });

  add(
    1,
    "Duplicate prevention — is this flow of traffic already allowed?",
    duplicate.duplicateStatus === "none" ? "pass" : "fail",
    duplicate.explanation,
    duplicate.matches.slice(0, 5).map((m) => m.citation),
  );

  add(
    2,
    "Zone traversal — which trust boundaries does this flow cross?",
    traversal.unknownZones.length > 0
      ? "fail"
      : (traversal.crossesUntrust || traversal.lowersTrust ||
          traversal.unrankedPairs.length > 0)
      ? "requires_human"
      : "pass",
    traversal.unknownZones.length > 0
      ? `Unknown zone(s): ${
        traversal.unknownZones.join(", ")
      }. No existing rule references them, so either the zone is new or the name is wrong.`
      : traversal.crossesUntrust
      ? "Crosses the untrust boundary. Escalation is a policy decision, not a lookup."
      : traversal.lowersTrust
      ? "Moves traffic into a less trusted zone. Whether that is acceptable is a judgment call."
      : traversal.unrankedPairs.length > 0
      ? `No trust rank configured for ${
        traversal.unrankedPairs.join(", ")
      }, so the trust direction could not be checked. Configure trustRank or have a human confirm it.`
      : `Stays inside the trust boundary across ${traversal.pairs.length} ranked zone pair(s).`,
  );

  const unresolved = [
    ...proposal.sourceAddress,
    ...proposal.destinationAddress,
  ].filter((n) =>
    n.toLowerCase() !== "any" && !resolver.hasAddress(n) &&
    parseCidr(n) === null
  );
  add(
    3,
    "Address objects — does every referenced address resolve?",
    unresolved.length === 0 ? "pass" : "fail",
    unresolved.length === 0
      ? "Every source and destination resolves to a defined object or a literal CIDR."
      : `Unresolved: ${
        unresolved.join(", ")
      }. These would need an address book entry first.`,
  );

  const unresolvedApps = proposal.application.filter((n) =>
    n.toLowerCase() !== "any" && !resolver.hasApplication(n) &&
    !n.startsWith("junos-")
  );
  add(
    4,
    "Applications — does every referenced application resolve?",
    unresolvedApps.length === 0 ? "pass" : "fail",
    unresolvedApps.length === 0
      ? "Every application resolves to a defined object, an application set, or a junos built-in."
      : `Unresolved: ${unresolvedApps.join(", ")}.`,
  );

  const usesAny = isAny(proposal.application);
  add(
    5,
    "Application scope — is `any` being used where a port would do?",
    usesAny ? "requires_human" : "pass",
    usesAny
      ? "Application is `any`. Whether that is defensible for this service is a judgment call."
      : `Scoped to ${proposal.application.length} named application(s).`,
  );

  const anySource = isAny(proposal.sourceAddress);
  const anyDest = isAny(proposal.destinationAddress);
  add(
    6,
    "Address scope — is `any` used on both ends?",
    anySource && anyDest ? "requires_human" : "pass",
    anySource && anyDest
      ? "Both source and destination are `any`. Intentional for diagnostics rules, rarely otherwise."
      : "At least one end is scoped to named addresses.",
  );

  let nameVerdict: Verdict = "requires_human";
  let nameDetail = "No naming pattern configured, so the name was not checked.";
  if (namePattern !== "") {
    try {
      const ok = new RegExp(namePattern).test(policyName);
      nameVerdict = ok ? "pass" : "fail";
      nameDetail = ok
        ? `Matches ${namePattern}.`
        : `"${policyName}" does not match ${namePattern}.`;
    } catch {
      nameDetail = `Naming pattern ${namePattern} is not a valid regex.`;
    }
  }
  add(
    7,
    "Naming — does the policy name follow convention?",
    nameVerdict,
    nameDetail,
  );

  const collision = snapshot.policies.find((p) => p.name === policyName);
  add(
    8,
    "Name collision — is this policy name already taken?",
    collision === undefined ? "pass" : "fail",
    collision === undefined
      ? "Name is unused."
      : `Already defined in ${collision.file}:${collision.line}.`,
    collision === undefined ? [] : [`${collision.file}:${collision.line}`],
  );

  for (
    const [id, item] of [
      [9, "Business justification — is the stated reason sufficient?"],
      [10, "Exploit scenario — what does this rule make possible if abused?"],
      [11, "Least privilege — could this be narrower and still work?"],
      [12, "Lifecycle — should this rule expire, and when?"],
    ] as Array<[number, string]>
  ) {
    add(
      id,
      item,
      "requires_human",
      "Judgment, not lookup. Left to a reviewer.",
    );
  }

  const passed = items.filter((i) => i.verdict === "pass").length;
  const failed = items.filter((i) => i.verdict === "fail").length;
  const requiresHuman =
    items.filter((i) => i.verdict === "requires_human").length;

  return {
    proposal,
    policyName,
    items,
    passed,
    failed,
    requiresHuman,
    mechanicallyClear: failed === 0,
    fetchedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

async function readPolicyDir(
  dir: string,
): Promise<Array<{ name: string; text: string }>> {
  // Preflight. Deno's raw NotFound on readDir names the syscall, not the
  // mistake — and the mistake is almost always a policyDir typo.
  let info: Deno.FileInfo;
  try {
    info = await Deno.stat(dir);
  } catch {
    throw new Error(
      `policyDir is not readable: ${dir} — check the path and permissions`,
    );
  }
  if (!info.isDirectory) {
    throw new Error(`policyDir is not a directory: ${dir}`);
  }

  const files: Array<{ name: string; text: string }> = [];
  for await (const entry of Deno.readDir(dir)) {
    if (!entry.isFile) continue;
    if (!/\.ya?ml$/.test(entry.name)) continue;
    files.push({
      name: entry.name,
      text: await Deno.readTextFile(`${dir}/${entry.name}`),
    });
  }
  if (files.length === 0) {
    throw new Error(
      `policyDir contains no .yml or .yaml files: ${dir} — an empty snapshot would make every duplicate check answer "none", which is the most dangerous wrong answer this model can give`,
    );
  }
  return files;
}

async function loadSnapshot(g: GlobalArgs): Promise<Snapshot> {
  const files = await readPolicyDir(g.policyDir);
  let mainTf = "";
  if (g.terraformMain !== "") {
    try {
      mainTf = await Deno.readTextFile(g.terraformMain);
    } catch {
      // A missing main.tf costs the unreferenced-file check, not the run.
      mainTf = "";
    }
  }
  return buildSnapshot(g.policyDir, files, mainTf, [
    ...DEFAULT_EXTERNAL_ADDRESS_PATTERNS,
    ...g.externalAddressPatterns,
  ]);
}

// ---------------------------------------------------------------------------

export const model = {
  type: "@hmcrum/juniper-policy",
  version: "2026.09.17.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    policy_snapshot: {
      description:
        "Every security policy, address object and application parsed from the policy tree, with the file and line each came from",
      schema: SnapshotSchema,
      lifetime: "1h" as const,
      garbageCollection: 5,
    },
    duplicate_check: {
      description:
        "Whether an existing permit rule already covers a proposed flow, exactly or by subsumption, with citations",
      schema: DuplicateResultSchema,
      lifetime: "infinite" as const,
      garbageCollection: 25,
    },
    zone_traversal: {
      description:
        "Trust boundaries a proposed flow crosses, and the rules that already exist for those zone pairs",
      schema: ZoneTraversalSchema,
      lifetime: "infinite" as const,
      garbageCollection: 25,
    },
    checklist: {
      description:
        "Per-item security review verdicts, separating mechanical answers from the ones needing a human",
      schema: ChecklistSchema,
      lifetime: "infinite" as const,
      garbageCollection: 25,
    },
  },

  methods: {
    load_policies: {
      description:
        "Parse every policy YAML in policyDir into one typed snapshot: rules, address objects, address sets, applications and application sets, each carrying its file and line. Also reports files no terraform role loads, references that resolve to nothing, and names defined twice — all invisible in the YAML itself. Read-only.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: ExecContext) => {
        const snapshot = await loadSnapshot(context.globalArgs);

        context.logger.info(
          "parsed {files} files: {policies} rules, {addresses} addresses, {applications} applications",
          {
            files: snapshot.fileCount,
            policies: snapshot.policyCount,
            addresses: snapshot.addressCount,
            applications: snapshot.applicationCount,
          },
        );
        if (snapshot.parseErrors.length > 0) {
          context.logger.warning("{count} file(s) failed to parse", {
            count: snapshot.parseErrors.length,
          });
        }
        if (snapshot.unreferencedFiles.length > 0) {
          context.logger.warning(
            "{count} policy file(s) loaded by no terraform role",
            { count: snapshot.unreferencedFiles.length },
          );
        }

        if (snapshot.danglingAddressRefs.length > 0) {
          context.logger.warning(
            "{count} address name(s) resolve to nothing and are not covered by externalAddressPatterns",
            { count: snapshot.danglingAddressRefs.length },
          );
        }

        await context.writeResource("policy_snapshot", "current", snapshot);
        return snapshot;
      },
    },

    find_duplicates: {
      description:
        "Given a proposed flow, return whether an existing permit rule already allows it: exact, subsumed, overlapping or none — never a boolean, because 'already covered by a broader rule' and 'partly allowed' lead to different decisions. Normalizes CIDR containment, address set membership, application sets and port ranges, and cites the matching rule's file and line. Read-only.",
      arguments: ProposalSchema,
      execute: async (
        args: z.infer<typeof ProposalSchema>,
        context: ExecContext,
      ) => {
        const snapshot = await loadSnapshot(context.globalArgs);
        const result = classifyProposal(snapshot, args);

        context.logger.info(
          "duplicate check: {status} over {considered} permit rules ({matches} candidate matches)",
          {
            status: result.duplicateStatus,
            considered: result.policiesConsidered,
            matches: result.matchCount,
          },
        );
        if (result.unknownReferences.length > 0) {
          context.logger.warning(
            "proposal references {count} undefined name(s): {names}",
            {
              count: result.unknownReferences.length,
              names: result.unknownReferences.join(", "),
            },
          );
        }

        await context.writeResource(
          "duplicate_check",
          resourceName(
            [...args.fromZone, "to", ...args.toZone],
            "duplicate-check",
          ),
          result,
        );
        return result;
      },
    },

    zone_traversal: {
      description:
        "Resolve a flow's zone pairs and report which trust boundaries it crosses, using the configured trust ranking rather than an inference. Emits the mermaid graph and the rules that already exist for those zone pairs, so the diagram in a review comes from parsed data. Read-only.",
      arguments: z.object({
        fromZone: z.array(z.string()).min(1).describe(
          "Source security zone(s)",
        ),
        toZone: z.array(z.string()).min(1).describe(
          "Destination security zone(s)",
        ),
      }),
      execute: async (
        args: { fromZone: string[]; toZone: string[] },
        context: ExecContext,
      ) => {
        const g = context.globalArgs;
        const snapshot = await loadSnapshot(g);
        const result = analyzeTraversal(
          snapshot,
          args.fromZone,
          args.toZone,
          g.untrustedZones,
          g.trustRank,
        );

        context.logger.info(
          "traversal {from} -> {to}: crossesUntrust={crosses}, {existing} existing rule(s)",
          {
            from: args.fromZone.join("+"),
            to: args.toZone.join("+"),
            crosses: result.crossesUntrust,
            existing: result.existingRuleCount,
          },
        );
        if (result.unknownZones.length > 0) {
          context.logger.warning("unknown zone(s): {zones}", {
            zones: result.unknownZones.join(", "),
          });
        }

        await context.writeResource(
          "zone_traversal",
          resourceName(
            [...args.fromZone, "to", ...args.toZone],
            "zone-traversal",
          ),
          result,
        );
        return result;
      },
    },

    evaluate_checklist: {
      description:
        "Answer the mechanically-answerable security review items for a proposed rule — duplicate status, zone traversal, address and application resolution, scope, naming, name collision — each with a verdict and file:line evidence. Items needing judgment return requires_human rather than a guess. Read-only.",
      arguments: ProposalSchema.extend({
        policyName: z.string().min(1).describe(
          "Proposed policy name, checked for convention and collision",
        ),
        namePattern: z.string().default("").describe(
          "Optional regex the policy name must match. Empty leaves the naming item to a human",
        ),
      }),
      execute: async (
        args: z.infer<typeof ProposalSchema> & {
          policyName: string;
          namePattern: string;
        },
        context: ExecContext,
      ) => {
        const g = context.globalArgs;
        const snapshot = await loadSnapshot(g);
        const result = evaluateChecklistItems(
          snapshot,
          {
            fromZone: args.fromZone,
            toZone: args.toZone,
            sourceAddress: args.sourceAddress,
            destinationAddress: args.destinationAddress,
            application: args.application,
          },
          args.policyName,
          g.untrustedZones,
          g.trustRank,
          args.namePattern,
        );

        context.logger.info(
          "checklist {name}: {passed} pass, {failed} fail, {human} for a human",
          {
            name: args.policyName,
            passed: result.passed,
            failed: result.failed,
            human: result.requiresHuman,
          },
        );

        await context.writeResource(
          "checklist",
          resourceName([args.policyName], "checklist"),
          result,
        );
        return result;
      },
    },
  },
};
