/**
 * Tests for @hmcrum/juniper-policy.
 *
 * Every fixture here is invented. No real zone name, address object, hostname
 * or policy name from any production tree appears in this file, and none should
 * ever be added — a published test suite that documents a live firewall posture
 * is a disclosure, not a test.
 *
 * The load-bearing test is `matches a rule against itself`. A parser that
 * cannot match a rule to its own definition will not match anything else
 * either, so that one assertion catches most normalization bugs for almost no
 * effort.
 *
 * @module
 */
import { assert, assertEquals, assertFalse } from "jsr:@std/assert@1.0.8";
import {
  analyzeTraversal,
  buildSnapshot,
  cidrContains,
  classifyProposal,
  evaluateChecklistItems,
  parseCidr,
  parsePortRange,
  parsePolicyFile,
  parseRolesToFiles,
  resourceName,
} from "./juniper_policy.ts";

// ---------------------------------------------------------------------------
// Synthetic fixtures
// ---------------------------------------------------------------------------

const ADDRESS_BOOK = `---
network_address:
  - name: net.example.servers
    value: 192.0.2.0/24
  - name: net.example.servers-v6
    value: 2001:db8:1::/48
  - name: host.example.alpha
    value: 192.0.2.10/32
  - name: host.example.beta
    value: 192.0.2.11/32
  - name: net.example.other
    value: 198.51.100.0/24
dns_name:
  - name: service.example.test
    value: service.example.test
address_set:
  - name: set.example.pair
    address:
      - host.example.alpha
      - host.example.beta
  - name: set.example.nested
    address_set:
      - set.example.pair
`;

const APPLICATIONS = `---
application:
  - name: app-https
    protocol: tcp
    destination_port: 443
  - name: app-highports
    protocol: tcp
    destination_port: 8000-8100
  - name: app-single-high
    protocol: tcp
    destination_port: 8050
  - name: app-udp-dns
    protocol: udp
    destination_port: 53
application_set:
  - name: set-web
    applications:
      - app-https
`;

const POLICIES = `---
# Synthetic policies. Zone names are placeholders.
policy:
  - name: alpha-permit-servers-https
    match_from_zone:
      - zone_a
    match_to_zone:
      - zone_b
    match_source_address:
      - net.example.servers
    match_destination_address:
      - net.example.other
    match_application:
      - app-https
    then: permit
    log_init: true
  - name: alpha-permit-broad-highports
    match_from_zone:
      - zone_a
      - zone_c
    match_to_zone:
      - zone_b
    match_source_address:
      - net.example.servers
    match_destination_address:
      - any
    match_application:
      - app-highports
    then: permit
  - name: alpha-permit-set-pair
    match_from_zone:
      - zone_c
    match_to_zone:
      - zone_b
    match_source_address:
      - set.example.nested
    match_destination_address:
      - net.example.other
    match_application:
      - set-web
    then: permit
  - name: alpha-deny-everything-else
    match_from_zone:
      - zone_a
    match_to_zone:
      - zone_untrusted
    match_source_address:
      - any
    match_destination_address:
      - any
    match_application:
      - any
    then: deny
`;

const MAIN_TF = `locals {
  policies = {
    role-one = [
      "./security-policies/_address_book.yml",
      "./security-policies/_applications.yml",
      "./security-policies/policies.yml"
    ]
    role-two = [
      "./security-policies/_address_book.yml",
      "./security-policies/policies.yml"
    ]
  }
}
`;

const snapshot = () =>
  buildSnapshot(
    "/synthetic",
    [
      { name: "_address_book.yml", text: ADDRESS_BOOK },
      { name: "_applications.yml", text: APPLICATIONS },
      { name: "policies.yml", text: POLICIES },
      { name: "orphan.yml", text: "---\npolicy: []\n" },
    ],
    MAIN_TF,
  );

// ---------------------------------------------------------------------------
// Address arithmetic
// ---------------------------------------------------------------------------

Deno.test("parseCidr treats a bare IPv4 address as a host route", () => {
  const cidr = parseCidr("192.0.2.10");
  assert(cidr !== null);
  assertEquals(cidr.prefix, 32);
  assertEquals(cidr.bits, 32);
});

Deno.test("parseCidr clears host bits", () => {
  const sloppy = parseCidr("192.0.2.77/24");
  const clean = parseCidr("192.0.2.0/24");
  assert(sloppy !== null && clean !== null);
  assertEquals(sloppy.network, clean.network);
});

Deno.test("parseCidr expands IPv6 elision", () => {
  const elided = parseCidr("2001:db8::1");
  const explicit = parseCidr("2001:0db8:0000:0000:0000:0000:0000:0001");
  assert(elided !== null && explicit !== null);
  assertEquals(elided.network, explicit.network);
  assertEquals(elided.bits, 128);
});

Deno.test("parseCidr rejects hostnames and malformed input", () => {
  assertEquals(parseCidr("service.example.test"), null);
  assertEquals(parseCidr("192.0.2.300"), null);
  assertEquals(parseCidr("192.0.2.0/33"), null);
  assertEquals(parseCidr("2001:db8::1::2"), null);
  assertEquals(parseCidr(""), null);
});

Deno.test("cidrContains is directional and family-aware", () => {
  const wide = parseCidr("192.0.2.0/24");
  const narrow = parseCidr("192.0.2.10/32");
  const v6 = parseCidr("2001:db8::/32");
  assert(wide !== null && narrow !== null && v6 !== null);
  assert(cidrContains(wide, narrow));
  assertFalse(cidrContains(narrow, wide));
  assertFalse(cidrContains(wide, v6));
  assert(cidrContains(wide, wide));
});

// ---------------------------------------------------------------------------
// Port arithmetic
// ---------------------------------------------------------------------------

Deno.test("parsePortRange handles single ports and ranges", () => {
  assertEquals(parsePortRange(443), { low: 443, high: 443 });
  assertEquals(parsePortRange("8000-8100"), { low: 8000, high: 8100 });
  assertEquals(parsePortRange("8100-8000"), null);
  assertEquals(parsePortRange("70000"), null);
  assertEquals(parsePortRange(""), null);
});

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

Deno.test("parsePolicyFile records file and line for every rule", () => {
  const parsed = parsePolicyFile("policies.yml", POLICIES);
  assertEquals(parsed.policies.length, 4);
  for (const rule of parsed.policies) {
    assertEquals(rule.file, "policies.yml");
    assert(rule.line > 0, `${rule.name} has no line number`);
  }
  // The line must actually point at the rule's own name.
  const lines = POLICIES.split("\n");
  for (const rule of parsed.policies) {
    assert(lines[rule.line - 1].includes(rule.name));
  }
});

Deno.test("parsePolicyFile preserves file order as evaluation order", () => {
  const parsed = parsePolicyFile("policies.yml", POLICIES);
  assertEquals(parsed.policies.map((p) => p.ordinal), [0, 1, 2, 3]);
});

Deno.test("parsePolicyFile reads both address_set member styles", () => {
  const parsed = parsePolicyFile("_address_book.yml", ADDRESS_BOOK);
  const pair = parsed.addresses.find((a) => a.name === "set.example.pair");
  const nested = parsed.addresses.find((a) => a.name === "set.example.nested");
  assertEquals(pair?.members, ["host.example.alpha", "host.example.beta"]);
  assertEquals(nested?.members, ["set.example.pair"]);
});

Deno.test("parseRolesToFiles maps each terraform role to its files", () => {
  const roles = parseRolesToFiles(MAIN_TF);
  assertEquals(Object.keys(roles).sort(), ["role-one", "role-two"]);
  assertEquals(roles["role-two"], ["_address_book.yml", "policies.yml"]);
});

Deno.test("buildSnapshot flags a file no role loads", () => {
  assertEquals(snapshot().unreferencedFiles, ["orphan.yml"]);
});

Deno.test("buildSnapshot finds no dangling references in a clean tree", () => {
  const snap = snapshot();
  assertEquals(snap.danglingAddressRefs, []);
  assertEquals(snap.danglingApplicationRefs, []);
  assertEquals(snap.parseErrors, []);
});

Deno.test("buildSnapshot flags a reference that resolves to nothing", () => {
  const snap = buildSnapshot("/synthetic", [
    { name: "_address_book.yml", text: ADDRESS_BOOK },
    { name: "_applications.yml", text: APPLICATIONS },
    {
      name: "bad.yml",
      text: `---
policy:
  - name: bad-rule
    match_from_zone: [zone_a]
    match_to_zone: [zone_b]
    match_source_address: [net.example.typo]
    match_destination_address: [any]
    match_application: [app-nonexistent]
    then: permit
`,
    },
  ], "");
  assertEquals(snap.danglingAddressRefs, ["net.example.typo"]);
  assertEquals(snap.danglingApplicationRefs, ["app-nonexistent"]);
});

Deno.test("junos built-ins and feeds are external, not dangling", () => {
  const snap = buildSnapshot("/synthetic", [
    { name: "_address_book.yml", text: ADDRESS_BOOK },
    { name: "_applications.yml", text: APPLICATIONS },
    {
      name: "external.yml",
      text: `---
policy:
  - name: external-rule
    match_from_zone: [zone_a]
    match_to_zone: [zone_b]
    match_source_address: [any-ipv6, feed_example_geo, net.example.typo]
    match_destination_address: [any]
    match_application: [app-https]
    then: permit
`,
    },
  ], "");
  // The one real typo must stay visible rather than being buried.
  assertEquals(snap.danglingAddressRefs, ["net.example.typo"]);
  assertEquals(snap.externalAddressRefs, ["any-ipv6", "feed_example_geo"]);
});

Deno.test("a configured external pattern moves a name out of dangling", () => {
  const files = [
    { name: "_address_book.yml", text: ADDRESS_BOOK },
    { name: "_applications.yml", text: APPLICATIONS },
    {
      name: "rendered.yml",
      text: `---
policy:
  - name: rendered-rule
    match_from_zone: [zone_a]
    match_to_zone: [zone_b]
    match_source_address: [rendered.per-device.thing]
    match_destination_address: [any]
    match_application: [app-https]
    then: permit
`,
    },
  ];
  const without = buildSnapshot("/synthetic", files, "");
  assertEquals(without.danglingAddressRefs, ["rendered.per-device.thing"]);

  const configured = buildSnapshot("/synthetic", files, "", [
    "^any$",
    "^rendered\\.",
  ]);
  assertEquals(configured.danglingAddressRefs, []);
  assertEquals(configured.externalAddressRefs, ["rendered.per-device.thing"]);
});

Deno.test("an invalid external pattern is ignored rather than fatal", () => {
  const snap = buildSnapshot("/synthetic", [
    { name: "_address_book.yml", text: ADDRESS_BOOK },
    { name: "policies.yml", text: POLICIES },
  ], "", ["([unclosed"]);
  assertEquals(snap.parseErrors, []);
  assertEquals(snap.policyCount, 4);
});

Deno.test("parseRolesToFiles ignores string lists that hold no policy files", () => {
  const roles = parseRolesToFiles(`locals {
  policies = {
    role-one = [
      "./security-policies/policies.yml"
    ]
  }
  depends_on = [
    "something_else"
  ]
}
`);
  assertEquals(Object.keys(roles), ["role-one"]);
});

Deno.test("buildSnapshot ignores junos built-in applications", () => {
  const snap = buildSnapshot("/synthetic", [
    { name: "_address_book.yml", text: ADDRESS_BOOK },
    {
      name: "builtin.yml",
      text: `---
policy:
  - name: builtin-rule
    match_from_zone: [zone_a]
    match_to_zone: [zone_b]
    match_source_address: [any]
    match_destination_address: [any]
    match_application: [junos-icmp-ping]
    then: permit
`,
    },
  ], "");
  assertEquals(snap.danglingApplicationRefs, []);
});

Deno.test("buildSnapshot collects zones and skips `any`", () => {
  const snap = snapshot();
  assertEquals(snap.zones, ["zone_a", "zone_b", "zone_c", "zone_untrusted"]);
});

Deno.test("buildSnapshot survives a broken file without losing the run", () => {
  const snap = buildSnapshot("/synthetic", [
    { name: "policies.yml", text: POLICIES },
    { name: "broken.yml", text: "policy:\n  - name: x\n   bad: [indent\n" },
  ], "");
  assertEquals(snap.parseErrors.length, 1);
  assertEquals(snap.parseErrors[0].file, "broken.yml");
  assertEquals(snap.policyCount, 4); // the good file still parsed
});

// ---------------------------------------------------------------------------
// Duplicate detection
//
// The self-match test comes first because it is the cheapest and catches the
// most: hand a rule its own definition back and it must find itself exactly.
// ---------------------------------------------------------------------------

Deno.test("matches a rule against itself", () => {
  const snap = snapshot();
  for (const rule of snap.policies.filter((p) => p.action === "permit")) {
    const result = classifyProposal(snap, {
      fromZone: rule.fromZones,
      toZone: rule.toZones,
      sourceAddress: rule.sourceAddresses,
      destinationAddress: rule.destinationAddresses,
      application: rule.applications,
    });
    assertEquals(
      result.duplicateStatus,
      "exact",
      `${rule.name} did not match itself`,
    );
    assertEquals(result.matchedPolicy, rule.name);
    assertEquals(result.matchedFile, rule.file);
    assert(result.matchedLine > 0);
  }
});

Deno.test("a host inside a permitted network is subsumed, not exact", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_a"],
    toZone: ["zone_b"],
    sourceAddress: ["host.example.alpha"], // /32 inside net.example.servers
    destinationAddress: ["net.example.other"],
    application: ["app-https"],
  });
  assertEquals(result.duplicateStatus, "subsumed");
  assertEquals(result.matchedPolicy, "alpha-permit-servers-https");
  assert(result.explanation.includes("broader"));
});

Deno.test("a literal CIDR inside a permitted network is subsumed", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_a"],
    toZone: ["zone_b"],
    sourceAddress: ["192.0.2.128/25"],
    destinationAddress: ["net.example.other"],
    application: ["app-https"],
  });
  assertEquals(result.duplicateStatus, "subsumed");
});

Deno.test("a port inside a permitted range is subsumed", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_a"],
    toZone: ["zone_b"],
    sourceAddress: ["net.example.servers"],
    destinationAddress: ["net.example.other"],
    application: ["app-single-high"], // 8050 inside 8000-8100
  });
  assertEquals(result.duplicateStatus, "subsumed");
  assertEquals(result.matchedPolicy, "alpha-permit-broad-highports");
});

Deno.test("a nested address_set member is subsumed", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_c"],
    toZone: ["zone_b"],
    sourceAddress: ["host.example.beta"], // via set.example.nested -> pair
    destinationAddress: ["net.example.other"],
    application: ["app-https"], // via set-web
  });
  assertEquals(result.duplicateStatus, "subsumed");
  assertEquals(result.matchedPolicy, "alpha-permit-set-pair");
});

Deno.test("a genuinely new flow returns none", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_b"],
    toZone: ["zone_c"],
    sourceAddress: ["net.example.other"],
    destinationAddress: ["net.example.servers"],
    application: ["app-udp-dns"],
  });
  assertEquals(result.duplicateStatus, "none");
  assertEquals(result.matchedPolicy, "");
  assertEquals(result.matchCount, 0);
});

Deno.test("a partly-covered flow returns overlapping, not subsumed", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_a"],
    toZone: ["zone_b"],
    sourceAddress: ["net.example.servers"],
    destinationAddress: ["net.example.other"],
    application: ["app-udp-dns"], // nothing permits udp/53 here
  });
  assertEquals(result.duplicateStatus, "overlapping");
  assertFalse(result.matches[0].covers.application);
  assert(result.matches[0].covers.source);
});

Deno.test("deny rules never count as a duplicate", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_a"],
    toZone: ["zone_untrusted"],
    sourceAddress: ["any"],
    destinationAddress: ["any"],
    application: ["any"],
  });
  assertEquals(result.duplicateStatus, "none");
});

Deno.test("a narrower rule does not cover a wider proposal", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_a"],
    toZone: ["zone_b"],
    sourceAddress: ["any"], // wider than net.example.servers
    destinationAddress: ["net.example.other"],
    application: ["app-https"],
  });
  assertEquals(result.duplicateStatus, "overlapping");
  assertFalse(result.matches[0].covers.source);
});

Deno.test("a zone the rule does not list is not covered", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_unlisted"],
    toZone: ["zone_b"],
    sourceAddress: ["net.example.servers"],
    destinationAddress: ["net.example.other"],
    application: ["app-https"],
  });
  assertEquals(result.duplicateStatus, "none");
});

Deno.test("undefined names in a proposal are reported, not silently ignored", () => {
  const result = classifyProposal(snapshot(), {
    fromZone: ["zone_a"],
    toZone: ["zone_b"],
    sourceAddress: ["net.example.doesnotexist"],
    destinationAddress: ["net.example.other"],
    application: ["app-alsomissing"],
  });
  assertEquals(result.unknownReferences, [
    "app-alsomissing",
    "net.example.doesnotexist",
  ]);
});

Deno.test("IPv6 containment works end to end", () => {
  const snap = buildSnapshot("/synthetic", [
    { name: "_address_book.yml", text: ADDRESS_BOOK },
    { name: "_applications.yml", text: APPLICATIONS },
    {
      name: "v6.yml",
      text: `---
policy:
  - name: v6-permit
    match_from_zone: [zone_a]
    match_to_zone: [zone_b]
    match_source_address: [net.example.servers-v6]
    match_destination_address: [any]
    match_application: [app-https]
    then: permit
`,
    },
  ], "");
  const result = classifyProposal(snap, {
    fromZone: ["zone_a"],
    toZone: ["zone_b"],
    sourceAddress: ["2001:db8:1:2::/64"],
    destinationAddress: ["net.example.other"],
    application: ["app-https"],
  });
  assertEquals(result.duplicateStatus, "subsumed");
});

// ---------------------------------------------------------------------------
// Zone traversal
// ---------------------------------------------------------------------------

Deno.test("traversal enumerates every zone pair", () => {
  const result = analyzeTraversal(
    snapshot(),
    ["zone_a", "zone_c"],
    ["zone_b"],
    ["zone_untrusted"],
    { zone_a: 50, zone_b: 50, zone_c: 40, zone_untrusted: 0 },
  );
  assertEquals(result.pairs.length, 2);
  assertFalse(result.crossesUntrust);
});

Deno.test("traversal reports crossing the untrust boundary as a fact", () => {
  const result = analyzeTraversal(
    snapshot(),
    ["zone_a"],
    ["zone_untrusted"],
    ["zone_untrusted"],
    {},
  );
  assert(result.crossesUntrust);
  assert(result.mermaid.includes("crosses untrust"));
});

Deno.test("traversal detects a drop in trust rank", () => {
  const result = analyzeTraversal(
    snapshot(),
    ["zone_a"],
    ["zone_c"],
    [],
    { zone_a: 90, zone_c: 20 },
  );
  assert(result.lowersTrust);
  assert(result.pairs[0].trustRanked);
  assertEquals(result.pairs[0].trustDelta, -70);
  assertEquals(result.unrankedPairs, []);
});

Deno.test("an unranked pair is reported as unranked, not as safe", () => {
  const result = analyzeTraversal(snapshot(), ["zone_a"], ["zone_c"], [], {});
  assertFalse(result.pairs[0].trustRanked);
  assertFalse(result.lowersTrust); // false means "not known", hence:
  assertEquals(result.unrankedPairs, ["zone_a -> zone_c"]);
});

Deno.test("a half-configured rank still counts as unranked", () => {
  const result = analyzeTraversal(
    snapshot(),
    ["zone_a"],
    ["zone_c"],
    [],
    { zone_a: 90 },
  );
  assertFalse(result.pairs[0].trustRanked);
  assertEquals(result.unrankedPairs, ["zone_a -> zone_c"]);
});

Deno.test("no zone taxonomy is shipped as a default", () => {
  // A default ranking would be one estate's topology published as a standard.
  const result = analyzeTraversal(
    snapshot(),
    ["zone_a", "zone_b", "zone_c", "zone_untrusted"],
    ["zone_b"],
    [],
    {},
  );
  assertEquals(result.unrankedPairs.length, result.pairs.length);
});

Deno.test("traversal flags a zone no rule mentions", () => {
  const result = analyzeTraversal(snapshot(), ["zone_typo"], ["zone_b"], [], {});
  assertEquals(result.unknownZones, ["zone_typo"]);
});

Deno.test("traversal lists the rules already covering the zone pair", () => {
  const result = analyzeTraversal(snapshot(), ["zone_a"], ["zone_b"], [], {});
  assertEquals(result.existingRuleCount, 2);
  assert(result.existingRules[0].includes("policies.yml:"));
});

// ---------------------------------------------------------------------------
// Checklist
// ---------------------------------------------------------------------------

Deno.test("checklist fails the duplicate item when a duplicate exists", () => {
  const result = evaluateChecklistItems(
    snapshot(),
    {
      fromZone: ["zone_a"],
      toZone: ["zone_b"],
      sourceAddress: ["host.example.alpha"],
      destinationAddress: ["net.example.other"],
      application: ["app-https"],
    },
    "beta-new-rule",
    [],
    {},
    "",
  );
  const duplicateItem = result.items.find((i) => i.id === 1);
  assertEquals(duplicateItem?.verdict, "fail");
  assert((duplicateItem?.evidence.length ?? 0) > 0);
  assertFalse(result.mechanicallyClear);
});

Deno.test("checklist passes a genuinely new, well-scoped rule", () => {
  const result = evaluateChecklistItems(
    snapshot(),
    {
      fromZone: ["zone_b"],
      toZone: ["zone_c"],
      sourceAddress: ["net.example.other"],
      destinationAddress: ["net.example.servers"],
      application: ["app-udp-dns"],
    },
    "beta-resolver-access",
    [],
    {},
    "^[a-z]+-[a-z_-]+$",
  );
  assertEquals(result.failed, 0);
  assert(result.mechanicallyClear);
});

Deno.test("checklist catches a policy name already in use", () => {
  const result = evaluateChecklistItems(
    snapshot(),
    {
      fromZone: ["zone_b"],
      toZone: ["zone_c"],
      sourceAddress: ["net.example.other"],
      destinationAddress: ["net.example.servers"],
      application: ["app-udp-dns"],
    },
    "alpha-permit-servers-https",
    [],
    {},
    "",
  );
  const collision = result.items.find((i) => i.id === 8);
  assertEquals(collision?.verdict, "fail");
  assertEquals(collision?.evidence.length, 1);
});

Deno.test("checklist abstains rather than guessing on judgment items", () => {
  const result = evaluateChecklistItems(
    snapshot(),
    {
      fromZone: ["zone_b"],
      toZone: ["zone_c"],
      sourceAddress: ["net.example.other"],
      destinationAddress: ["net.example.servers"],
      application: ["app-udp-dns"],
    },
    "beta-resolver-access",
    [],
    {},
    "",
  );
  // Four judgment items plus the unconfigured naming check.
  assert(result.requiresHuman >= 5);
  for (const id of [9, 10, 11, 12]) {
    assertEquals(result.items.find((i) => i.id === id)?.verdict, "requires_human");
  }
});

Deno.test("checklist escalates an untrust crossing to a human", () => {
  const result = evaluateChecklistItems(
    snapshot(),
    {
      fromZone: ["zone_a"],
      toZone: ["zone_untrusted"],
      sourceAddress: ["net.example.servers"],
      destinationAddress: ["net.example.other"],
      application: ["app-https"],
    },
    "beta-egress",
    ["zone_untrusted"],
    {},
    "",
  );
  assertEquals(result.items.find((i) => i.id === 2)?.verdict, "requires_human");
});

Deno.test("checklist flags `any` on both address ends", () => {
  const result = evaluateChecklistItems(
    snapshot(),
    {
      fromZone: ["zone_b"],
      toZone: ["zone_c"],
      sourceAddress: ["any"],
      destinationAddress: ["any"],
      application: ["app-udp-dns"],
    },
    "beta-wide",
    [],
    {},
    "",
  );
  assertEquals(result.items.find((i) => i.id === 6)?.verdict, "requires_human");
});

Deno.test("checklist fails a name that breaks the configured pattern", () => {
  const result = evaluateChecklistItems(
    snapshot(),
    {
      fromZone: ["zone_b"],
      toZone: ["zone_c"],
      sourceAddress: ["net.example.other"],
      destinationAddress: ["net.example.servers"],
      application: ["app-udp-dns"],
    },
    "BadName!!",
    [],
    {},
    "^[a-z]+-[a-z_]+$",
  );
  assertEquals(result.items.find((i) => i.id === 7)?.verdict, "fail");
});

// ---------------------------------------------------------------------------
// Resource naming
//
// Zone and policy names are caller input and become data resource names.
// ---------------------------------------------------------------------------

Deno.test("resourceName strips characters unsafe for a resource name", () => {
  assertEquals(resourceName(["Zone A", "to", "Zone/B"], "fb"), "zone-a-to-zone-b");
  assertEquals(resourceName(["policy!!name"], "fb"), "policy-name");
  assertEquals(resourceName(["a  b"], "fb"), "a-b");
});

Deno.test("resourceName falls back rather than returning an empty name", () => {
  assertEquals(resourceName(["!!!"], "fallback"), "fallback");
  assertEquals(resourceName([""], "fallback"), "fallback");
});

Deno.test("resourceName never leads or trails with a separator", () => {
  const name = resourceName(["--weird--"], "fb");
  assertFalse(name.startsWith("-"));
  assertFalse(name.endsWith("-"));
});

Deno.test("resourceName bounds the length", () => {
  assert(resourceName(["x".repeat(500)], "fb").length <= 80);
});

Deno.test("resourceName keeps dots, which address names rely on", () => {
  assertEquals(resourceName(["net.example.servers"], "fb"), "net.example.servers");
});
