/**
 * Tests for @hmcrum/eol-lifecycle.
 *
 * All fixtures are invented cycle data shaped like endoflife.date's real
 * response, not fetched from the live API — `withMockedFetch` stands in for
 * the network so these run offline and deterministically.
 *
 * @module
 */
import { assertEquals } from "jsr:@std/assert@1.0.8";
import {
  createModelTestContext,
  withMockedFetch,
} from "jsr:@swamp-club/swamp-testing@0.20260917.35";
import { model } from "./eol_lifecycle.ts";

type LifecycleArgs = Parameters<typeof model.methods.lifecycle.execute>[0];
type LifecycleContext = Parameters<typeof model.methods.lifecycle.execute>[1];

/**
 * `createModelTestContext`'s `globalArgs` is typed `Record<string, unknown>`,
 * which can't structurally satisfy the model's narrower `{ userAgent: string }`
 * context type — this wrapper is the one cast that absorbs that mismatch.
 */
function runLifecycle(args: LifecycleArgs, context: unknown) {
  return model.methods.lifecycle.execute(args, context as LifecycleContext);
}

Deno.test("lifecycle marks a cycle unsupported once its eol date has passed", async () => {
  const { context, getWrittenResources } = createModelTestContext({ globalArgs: { userAgent: "swamp-eol-lifecycle-test/1.0" } });

  await withMockedFetch(
    (req) => {
      assertEquals(new URL(req.url).hostname, "endoflife.date");
      return new Response(
        JSON.stringify([
          { cycle: "9", releaseDate: "2020-01-01", eol: "2021-01-01", latest: "9.9.9" },
          { cycle: "10", releaseDate: "2030-01-01", eol: "2099-01-01", latest: "10.0.0" },
        ]),
        { status: 200 },
      );
    },
    async () => {
      await runLifecycle({ product: "widget" }, context);
    },
  );

  const written = getWrittenResources()[0].data as {
    found: boolean;
    anyEol: boolean;
    cycles: Array<{ cycle: string; supported: boolean }>;
  };
  assertEquals(written.found, true);
  assertEquals(written.anyEol, true);
  assertEquals(
    written.cycles.find((c) => c.cycle === "9")?.supported,
    false,
  );
  assertEquals(
    written.cycles.find((c) => c.cycle === "10")?.supported,
    true,
  );
});

Deno.test("lifecycle treats a boolean eol:false as permanently supported", async () => {
  const { context, getWrittenResources } = createModelTestContext({ globalArgs: { userAgent: "swamp-eol-lifecycle-test/1.0" } });

  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify([
          { cycle: "rolling", releaseDate: "2020-01-01", eol: false, latest: "1.0.0" },
        ]),
        { status: 200 },
      ),
    async () => {
      await runLifecycle({ product: "widget" }, context);
    },
  );

  const written = getWrittenResources()[0].data as {
    anyEol: boolean;
    cycles: Array<{ eolDate: unknown; supported: boolean }>;
  };
  assertEquals(written.cycles[0].eolDate, false);
  assertEquals(written.cycles[0].supported, true);
  assertEquals(written.anyEol, false);
});

Deno.test("lifecycle treats a boolean eol:true as already ended", async () => {
  const { context, getWrittenResources } = createModelTestContext({ globalArgs: { userAgent: "swamp-eol-lifecycle-test/1.0" } });

  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify([
          { cycle: "1", releaseDate: "2020-01-01", eol: true, latest: "1.0.0" },
        ]),
        { status: 200 },
      ),
    async () => {
      await runLifecycle({ product: "widget" }, context);
    },
  );

  const written = getWrittenResources()[0].data as {
    anyEol: boolean;
    cycles: Array<{ supported: boolean }>;
  };
  assertEquals(written.cycles[0].supported, false);
  assertEquals(written.anyEol, true);
});

Deno.test("lifecycle filters to the requested cycle only", async () => {
  const { context, getWrittenResources } = createModelTestContext({ globalArgs: { userAgent: "swamp-eol-lifecycle-test/1.0" } });

  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify([
          { cycle: "9", releaseDate: "2020-01-01", eol: "2021-01-01", latest: "9.9.9" },
          { cycle: "10", releaseDate: "2030-01-01", eol: "2099-01-01", latest: "10.0.0" },
        ]),
        { status: 200 },
      ),
    async () => {
      await runLifecycle(
        { product: "widget", cycle: "10" },
        context,
      );
    },
  );

  const written = getWrittenResources()[0].data as {
    requestedCycle: string | null;
    cycles: Array<{ cycle: string }>;
    anyEol: boolean;
    note: string | null;
  };
  assertEquals(written.requestedCycle, "10");
  assertEquals(written.cycles.length, 1);
  assertEquals(written.cycles[0].cycle, "10");
  assertEquals(written.anyEol, false);
  assertEquals(written.note, null);
});

Deno.test("lifecycle notes a requested cycle that doesn't exist, without throwing", async () => {
  const { context, getWrittenResources } = createModelTestContext({ globalArgs: { userAgent: "swamp-eol-lifecycle-test/1.0" } });

  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify([
          { cycle: "10", releaseDate: "2030-01-01", eol: "2099-01-01", latest: "10.0.0" },
        ]),
        { status: 200 },
      ),
    async () => {
      await runLifecycle(
        { product: "widget", cycle: "99" },
        context,
      );
    },
  );

  const written = getWrittenResources()[0].data as {
    found: boolean;
    cycles: unknown[];
    note: string | null;
  };
  assertEquals(written.found, true);
  assertEquals(written.cycles.length, 0);
  assertEquals(
    written.note,
    'product "widget" was found, but has no cycle "99". Available cycles: 10.',
  );
});

Deno.test("lifecycle degrades on a 404 with catalog suggestions, never throws", async () => {
  const { context, getWrittenResources } = createModelTestContext({ globalArgs: { userAgent: "swamp-eol-lifecycle-test/1.0" } });

  await withMockedFetch(
    (req) => {
      const url = new URL(req.url);
      if (url.pathname === "/api/all.json") {
        return new Response(JSON.stringify(["widget", "widgy", "gadget"]), {
          status: 200,
        });
      }
      return new Response("not found", { status: 404 });
    },
    async () => {
      await runLifecycle({ product: "widgett" }, context);
    },
  );

  const written = getWrittenResources()[0].data as {
    found: boolean;
    cycles: unknown[];
    anyEol: boolean;
    suggestions: string[];
    note: string | null;
  };
  assertEquals(written.found, false);
  assertEquals(written.cycles, []);
  assertEquals(written.anyEol, false);
  // "widgy" shares no substring relation with "widgett" (only "widget" does),
  // so it correctly does not surface as a suggestion here.
  assertEquals(written.suggestions, ["widget"]);
  assertEquals(
    written.note,
    'endoflife.date has no product "widgett". Close matches: widget.',
  );
});

Deno.test("lifecycle degrades on a 404 even when the catalog lookup itself fails", async () => {
  const { context, getWrittenResources } = createModelTestContext({ globalArgs: { userAgent: "swamp-eol-lifecycle-test/1.0" } });

  await withMockedFetch(
    (req) => {
      const url = new URL(req.url);
      if (url.pathname === "/api/all.json") {
        return new Response("boom", { status: 500 });
      }
      return new Response("not found", { status: 404 });
    },
    async () => {
      await runLifecycle({ product: "widgett" }, context);
    },
  );

  const written = getWrittenResources()[0].data as {
    found: boolean;
    suggestions: string[];
    note: string | null;
  };
  assertEquals(written.found, false);
  assertEquals(written.suggestions, []);
  assertEquals(
    written.note,
    'endoflife.date has no product "widgett" and no close match was found in its catalog.',
  );
});

Deno.test("lifecycle throws on a non-404 error instead of writing a resource", async () => {
  const { context, getWrittenResources } = createModelTestContext({ globalArgs: { userAgent: "swamp-eol-lifecycle-test/1.0" } });

  let threw = false;
  await withMockedFetch(
    () => new Response("upstream on fire", { status: 500 }),
    async () => {
      try {
        await runLifecycle({ product: "widget" }, context);
      } catch {
        threw = true;
      }
    },
  );

  assertEquals(threw, true);
  assertEquals(getWrittenResources().length, 0);
});
