/**
 * Unit tests for the Statuspage component model.
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./statuspage_component.ts";

interface FetchCall {
  url: string;
  method: string;
  body: unknown;
}

/** Build a mocked test context plus a fetch stub over a response queue. */
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
      name: "API",
      description: "The API",
      status: "operational" as const,
      showcase: true,
    },
    logger: { info: noop, warning: noop },
    readResource: (name: string) =>
      Promise.resolve(store.get(name) ?? null),
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

const apiComponent = {
  id: "cmp1",
  page_id: "page1",
  name: "API",
  status: "operational",
  description: "The API",
  group_id: null,
  showcase: true,
  position: 1,
  created_at: "2026-09-17T00:00:00Z",
  updated_at: "2026-09-17T00:00:00Z",
};

Deno.test("component create posts to the components endpoint and stores state", async () => {
  const { context, calls, store, restore } = makeHarness([
    { status: 201, json: apiComponent },
  ]);
  try {
    const result = await model.methods.create.execute({}, context);
    assertEquals(calls[0].method, "POST");
    assertEquals(
      calls[0].url,
      "https://api.statuspage.io/v1/pages/page1/components",
    );
    assertEquals((calls[0].body as { component: { name: string } }).component.name, "API");
    assertEquals(result.dataHandles.length, 1);
    assertEquals(store.get("main")?.id, "cmp1");
  } finally {
    restore();
  }
});

Deno.test("component create is idempotent when state exists and resource is live", async () => {
  const { context, calls, restore } = makeHarness(
    [{ status: 200, json: apiComponent }],
    { id: "cmp1" },
  );
  try {
    await model.methods.create.execute({}, context);
    // Should GET the existing component, not POST a new one.
    assertEquals(calls[0].method, "GET");
    assertEquals(
      calls[0].url,
      "https://api.statuspage.io/v1/pages/page1/components/cmp1",
    );
  } finally {
    restore();
  }
});

Deno.test("component create recreates when stored resource is gone (404)", async () => {
  const { context, calls, restore } = makeHarness(
    [
      { status: 404 },
      { status: 201, json: apiComponent },
    ],
    { id: "stale" },
  );
  try {
    await model.methods.create.execute({}, context);
    assertEquals(calls[0].method, "GET");
    assertEquals(calls[1].method, "POST");
  } finally {
    restore();
  }
});

Deno.test("component update patches the component", async () => {
  const { context, calls, restore } = makeHarness(
    [{ status: 200, json: { ...apiComponent, status: "major_outage" } }],
    { id: "cmp1" },
  );
  try {
    context.globalArgs.status = "major_outage" as never;
    const result = await model.methods.update.execute({}, context);
    assertEquals(calls[0].method, "PATCH");
    assertEquals(
      calls[0].url,
      "https://api.statuspage.io/v1/pages/page1/components/cmp1",
    );
    assertEquals(result.dataHandles.length, 1);
  } finally {
    restore();
  }
});

Deno.test("component update throws without prior state", async () => {
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

Deno.test("component delete issues DELETE and clears handles", async () => {
  const { context, calls, restore } = makeHarness(
    [{ status: 204 }],
    { id: "cmp1" },
  );
  try {
    const result = await model.methods.delete.execute({}, context);
    assertEquals(calls[0].method, "DELETE");
    assertEquals(result.dataHandles.length, 0);
  } finally {
    restore();
  }
});

Deno.test("component delete tolerates already-deleted (404)", async () => {
  const { context, restore } = makeHarness(
    [{ status: 404 }],
    { id: "cmp1" },
  );
  try {
    const result = await model.methods.delete.execute({}, context);
    assertEquals(result.dataHandles.length, 0);
  } finally {
    restore();
  }
});

Deno.test("component sync writes not_found marker when resource is gone", async () => {
  const { context, store, restore } = makeHarness(
    [{ status: 404 }],
    { ...apiComponent },
  );
  try {
    await model.methods.sync.execute({}, context);
    assertEquals(store.get("main")?.status, "not_found");
  } finally {
    restore();
  }
});
