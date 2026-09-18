/**
 * Unit tests for the Statuspage incident model.
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./statuspage_incident.ts";

interface FetchCall {
  url: string;
  method: string;
  body: unknown;
}

function makeHarness(
  responses: Array<{ status: number; json?: unknown }>,
  seed?: Record<string, unknown>,
) {
  const calls: FetchCall[] = [];
  let idx = 0;
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    const r = responses[idx++] ?? { status: 200, json: {} };
    return Promise.resolve(
      new Response(
        r.status === 204 ? null : JSON.stringify(r.json ?? {}),
        { status: r.status },
      ),
    );
  }) as typeof fetch;

  const store = new Map<string, Record<string, unknown>>();
  if (seed) store.set("main", seed);

  const noop = () => {};
  const context = {
    globalArgs: {
      pageId: "page1",
      apiKey: "secret",
      name: "Outage",
      status: "investigating" as const,
      body: "Looking into it",
      componentIds: [] as string[],
      deliverNotifications: true,
    },
    logger: { info: noop, warning: noop },
    readResource: (name: string) => Promise.resolve(store.get(name) ?? null),
    writeResource: (
      _spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      store.set(name, data);
      return Promise.resolve({ name });
    },
  };

  const restore = () => {
    globalThis.fetch = original;
  };
  return { context, calls, store, restore };
}

const apiIncident = {
  id: "inc1",
  page_id: "page1",
  name: "Outage",
  status: "investigating",
  impact: "major",
  shortlink: "http://stspg.io/abc",
  components: [{ id: "cmp1" }],
  created_at: "2026-09-17T00:00:00Z",
  updated_at: "2026-09-17T00:00:00Z",
  resolved_at: null,
};

Deno.test("incident create posts and normalises component ids", async () => {
  const { context, calls, store, restore } = makeHarness([
    { status: 201, json: apiIncident },
  ]);
  try {
    const result = await model.methods.create.execute({}, context);
    assertEquals(calls[0].method, "POST");
    assertEquals(
      calls[0].url,
      "https://api.statuspage.io/v1/pages/page1/incidents",
    );
    assertEquals(result.dataHandles.length, 1);
    assertEquals(store.get("main")?.component_ids, ["cmp1"]);
  } finally {
    restore();
  }
});

Deno.test("incident create includes impact_override and component_ids when set", async () => {
  const { context, calls, restore } = makeHarness([
    { status: 201, json: apiIncident },
  ]);
  try {
    context.globalArgs.componentIds = ["cmp1", "cmp2"];
    (context.globalArgs as { impactOverride?: string }).impactOverride = "critical";
    await model.methods.create.execute({}, context);
    const body = calls[0].body as { incident: Record<string, unknown> };
    assertEquals(body.incident.impact_override, "critical");
    assertEquals(body.incident.component_ids, ["cmp1", "cmp2"]);
  } finally {
    restore();
  }
});

Deno.test("incident resolve patches status to resolved", async () => {
  const { context, calls, store, restore } = makeHarness(
    [{
      status: 200,
      json: { ...apiIncident, status: "resolved", resolved_at: "2026-09-17T01:00:00Z" },
    }],
    { id: "inc1" },
  );
  try {
    const result = await model.methods.resolve.execute(
      { body: "All clear" },
      context,
    );
    assertEquals(calls[0].method, "PATCH");
    const body = calls[0].body as { incident: Record<string, unknown> };
    assertEquals(body.incident.status, "resolved");
    assertEquals(body.incident.body, "All clear");
    assertEquals(store.get("main")?.status, "resolved");
    assertEquals(result.dataHandles.length, 1);
  } finally {
    restore();
  }
});

Deno.test("incident update throws without prior state", async () => {
  const { context, restore } = makeHarness([]);
  try {
    await assertRejects(
      () => model.methods.update.execute({}, context),
      Error,
      "run create first",
    );
  } finally {
    restore();
  }
});

Deno.test("incident delete issues DELETE and clears handles", async () => {
  const { context, calls, restore } = makeHarness(
    [{ status: 200, json: apiIncident }],
    { id: "inc1" },
  );
  try {
    const result = await model.methods.delete.execute({}, context);
    assertEquals(calls[0].method, "DELETE");
    assertEquals(result.dataHandles.length, 0);
  } finally {
    restore();
  }
});

Deno.test("incident sync writes not_found marker when gone", async () => {
  const { context, store, restore } = makeHarness(
    [{ status: 404 }],
    { ...apiIncident },
  );
  try {
    await model.methods.sync.execute({}, context);
    assertEquals(store.get("main")?.status, "not_found");
  } finally {
    restore();
  }
});
