/**
 * Unit tests for the shared Statuspage API client.
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  NotFoundError,
  STATUSPAGE_BASE_URL,
  statuspageRequest,
} from "./statuspage.ts";

/** Replace globalThis.fetch with a stub for the duration of `fn`. */
async function withMockedFetch(
  handler: (input: string | URL | Request, init?: RequestInit) => Response,
  fn: () => Promise<void>,
): Promise<void> {
  const original = globalThis.fetch;
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    return Promise.resolve(handler(input, init));
  }) as typeof fetch;
  (globalThis as { __fetchCalls?: unknown }).__fetchCalls = calls;
  try {
    await fn();
  } finally {
    globalThis.fetch = original;
  }
}

Deno.test("statuspageRequest sends OAuth header and parses JSON", async () => {
  await withMockedFetch(
    (_input, init) => {
      const headers = new Headers(init?.headers);
      assertEquals(headers.get("Authorization"), "OAuth secret-token");
      assertEquals(headers.get("Content-Type"), "application/json");
      return new Response(JSON.stringify({ id: "abc", name: "API" }), {
        status: 200,
      });
    },
    async () => {
      const result = await statuspageRequest<{ id: string; name: string }>(
        "/pages/p1/components/abc",
        { apiKey: "secret-token" },
      );
      assertEquals(result, { id: "abc", name: "API" });
    },
  );
});

Deno.test("statuspageRequest targets the correct base URL", async () => {
  await withMockedFetch(
    (input) => {
      assertEquals(
        String(input),
        `${STATUSPAGE_BASE_URL}/pages/p1/components`,
      );
      return new Response("[]", { status: 200 });
    },
    async () => {
      await statuspageRequest("/pages/p1/components", { apiKey: "k" });
    },
  );
});

Deno.test("statuspageRequest serialises the body for POST", async () => {
  await withMockedFetch(
    (_input, init) => {
      assertEquals(init?.method, "POST");
      assertEquals(init?.body, JSON.stringify({ component: { name: "API" } }));
      return new Response(JSON.stringify({ id: "new" }), { status: 201 });
    },
    async () => {
      const res = await statuspageRequest<{ id: string }>(
        "/pages/p1/components",
        { method: "POST", apiKey: "k", body: { component: { name: "API" } } },
      );
      assertEquals(res.id, "new");
    },
  );
});

Deno.test("statuspageRequest returns null on 204", async () => {
  await withMockedFetch(
    () => new Response(null, { status: 204 }),
    async () => {
      const res = await statuspageRequest<null>("/pages/p1/components/x", {
        method: "DELETE",
        apiKey: "k",
      });
      assertEquals(res, null);
    },
  );
});

Deno.test("statuspageRequest throws NotFoundError on 404", async () => {
  await withMockedFetch(
    () => new Response(JSON.stringify({ message: "not found" }), {
      status: 404,
    }),
    async () => {
      await assertRejects(
        () => statuspageRequest("/pages/p1/components/missing", { apiKey: "k" }),
        NotFoundError,
      );
    },
  );
});

Deno.test("statuspageRequest throws descriptive error with status and body", async () => {
  await withMockedFetch(
    () => new Response("validation failed", { status: 422 }),
    async () => {
      await assertRejects(
        () => statuspageRequest("/pages/p1/incidents", {
          method: "POST",
          apiKey: "k",
        }),
        Error,
        "422",
      );
    },
  );
});

Deno.test("statuspageRequest retries on 429 then succeeds", async () => {
  let attempts = 0;
  await withMockedFetch(
    () => {
      attempts++;
      if (attempts === 1) {
        return new Response("rate limited", {
          status: 429,
          headers: { "Retry-After": "0" },
        });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    },
    async () => {
      const res = await statuspageRequest<{ ok: boolean }>(
        "/pages/p1/components",
        { apiKey: "k", maxAttempts: 3 },
      );
      assertEquals(res.ok, true);
      assertEquals(attempts, 2);
    },
  );
});
