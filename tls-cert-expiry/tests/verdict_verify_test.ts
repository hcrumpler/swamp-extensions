import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "../models/tls_cert_expiry.ts";

async function openssl(args: string[]): Promise<string> {
  const out = await new Deno.Command("openssl", { args }).output();
  assert(out.success, new TextDecoder().decode(out.stderr));
  return new TextDecoder().decode(out.stdout);
}

function freePort(): number {
  const l = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (l.addr as Deno.NetAddr).port;
  l.close();
  return port;
}

/** Writes a throwaway self-signed cert and key; returns the cert's fingerprint as lowercase hex. */
async function makeCert(
  dir: string,
  name: string,
  days: number,
): Promise<string> {
  await openssl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    `${dir}/${name}.key`,
    "-out",
    `${dir}/${name}.pem`,
    "-days",
    String(days),
    "-subj",
    `/CN=${name}`,
  ]);
  const out = await openssl([
    "x509",
    "-noout",
    "-fingerprint",
    "-sha256",
    "-in",
    `${dir}/${name}.pem`,
  ]);
  return out.match(/Fingerprint=(.+)$/m)![1].replaceAll(":", "").toLowerCase();
}

/** Runs `body` against an `openssl s_server` on a free port; `extra` adds s_server arguments. */
async function withServer(
  dir: string,
  cert: string,
  extra: string[],
  body: (port: number) => Promise<void>,
) {
  const port = freePort();
  const server = new Deno.Command("openssl", {
    args: [
      "s_server",
      "-accept",
      `127.0.0.1:${port}`,
      "-cert",
      `${dir}/${cert}.pem`,
      "-key",
      `${dir}/${cert}.key`,
      ...extra,
      "-quiet",
    ],
    stdin: "piped",
    stdout: "null",
    stderr: "null",
  }).spawn();
  try {
    for (let i = 0;; i++) {
      try {
        (await Deno.connect({ hostname: "127.0.0.1", port })).close();
        break;
      } catch (e) {
        if (i > 50) throw e;
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    await body(port);
  } finally {
    try {
      server.kill("SIGKILL");
    } catch { /* gone */ }
    await server.status;
  }
}

type Inputs = {
  hosts: string[];
  expectFingerprint?: string;
  minDays?: number;
  serverName?: string;
};

function context(written: Record<string, Record<string, unknown>>) {
  return {
    globalArgs: {
      warnThresholdDays: 30,
      criticalThresholdDays: 7,
      timeoutSec: 10,
    },
    logger: { info: () => {} },
    writeResource: (
      _spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      written[name] = data;
      return Promise.resolve({ name });
    },
  };
}

async function runCheck(inputs: Inputs, port: number) {
  const written: Record<string, Record<string, unknown>> = {};
  await model.methods.check.execute(
    { defaultPort: 443, ...inputs },
    context(written),
  );
  return written[`cert-127-0-0-1-${port}`];
}

function runVerify(inputs: Inputs) {
  const written: Record<string, Record<string, unknown>> = {};
  return {
    written,
    done: model.methods.verify.execute(
      { defaultPort: 443, ...inputs },
      context(written),
    ),
  };
}

async function withTempDir(body: (dir: string) => Promise<void>) {
  const dir = await Deno.makeTempDir();
  try {
    await body(dir);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

Deno.test("verdict is ok when nothing is expected or the expectations hold", async () => {
  await withTempDir(async (dir) => {
    const fp = await makeCert(dir, "a", 90);
    await withServer(dir, "a", [], async (port) => {
      const host = `127.0.0.1:${port}`;
      for (
        const extra of [{}, { expectFingerprint: fp, minDays: 30 }]
      ) {
        const r = await runCheck({ hosts: [host], ...extra }, port);
        assertEquals(r.verdict, "ok");
        assertEquals(r.cause, null);
        assertEquals(r.status, "ok");
      }
    });
  });
});

Deno.test("verdict is other-certificate when the fingerprint differs, naming both", async () => {
  await withTempDir(async (dir) => {
    const fp = await makeCert(dir, "a", 90);
    const other = await makeCert(dir, "b", 90);
    await withServer(dir, "a", [], async (port) => {
      const r = await runCheck(
        { hosts: [`127.0.0.1:${port}`], expectFingerprint: other },
        port,
      );
      assertEquals(r.verdict, "other-certificate");
      assert((r.cause as string).includes(fp));
      assert((r.cause as string).includes(other));
    });
  });
});

Deno.test("other-certificate wins over expiring", async () => {
  await withTempDir(async (dir) => {
    await makeCert(dir, "a", 10);
    const other = await makeCert(dir, "b", 90);
    await withServer(dir, "a", [], async (port) => {
      const r = await runCheck(
        { hosts: [`127.0.0.1:${port}`], expectFingerprint: other, minDays: 20 },
        port,
      );
      assertEquals(r.verdict, "other-certificate");
    });
  });
});

Deno.test("verdict is expiring when days remaining are below minDays", async () => {
  await withTempDir(async (dir) => {
    await makeCert(dir, "a", 10);
    await withServer(dir, "a", [], async (port) => {
      const r = await runCheck(
        { hosts: [`127.0.0.1:${port}`], minDays: 20 },
        port,
      );
      assertEquals(r.verdict, "expiring");
      assert((r.cause as string).includes("minDays is 20"));
      assert((r.cause as string).includes(`${r.daysRemaining} day(s)`));
    });
  });
});

Deno.test("verdict is unreachable for a closed port, with the probe error as cause", async () => {
  const port = freePort();
  const r = await runCheck({ hosts: [`127.0.0.1:${port}`], minDays: 1 }, port);
  assertEquals(r.verdict, "unreachable");
  assertEquals(r.cause, r.error);
  assert(r.error !== null);
});

Deno.test("expectFingerprint with colons, spaces and uppercase still matches", async () => {
  await withTempDir(async (dir) => {
    const fp = await makeCert(dir, "a", 90);
    const messy = fp.toUpperCase().match(/../g)!.join(":");
    await withServer(dir, "a", [], async (port) => {
      for (
        const expectFingerprint of [messy, ` ${messy.replaceAll(":", " ")} `]
      ) {
        const r = await runCheck(
          { hosts: [`127.0.0.1:${port}`], expectFingerprint },
          port,
        );
        assertEquals(r.verdict, "ok");
      }
    });
  });
});

Deno.test("an expectFingerprint that is not 64 hex characters is rejected", async () => {
  for (const bad of ["", "abc", "zz".repeat(32), "ab".repeat(33)]) {
    await assertRejects(
      () => runCheck({ hosts: ["127.0.0.1:1"], expectFingerprint: bad }, 1),
      Error,
      "64 hex characters",
    );
  }
});

Deno.test("serverName is sent as SNI and the served certificate follows it", async () => {
  await withTempDir(async (dir) => {
    const fpDefault = await makeCert(dir, "a", 90);
    const fpSni = await makeCert(dir, "b", 90);
    assert(fpDefault !== fpSni);
    await withServer(
      dir,
      "a",
      [
        "-servername",
        "sni.example",
        "-cert2",
        `${dir}/b.pem`,
        "-key2",
        `${dir}/b.key`,
      ],
      async (port) => {
        const host = `127.0.0.1:${port}`;
        const plain = await runCheck({ hosts: [host] }, port);
        assertEquals(plain.fingerprintSha256, fpDefault);
        const named = await runCheck(
          { hosts: [host], serverName: "sni.example" },
          port,
        );
        assertEquals(named.fingerprintSha256, fpSni);
      },
    );
  });
});

Deno.test("verify returns normally for ok and still writes the results", async () => {
  await withTempDir(async (dir) => {
    const fp = await makeCert(dir, "a", 90);
    await withServer(dir, "a", [], async (port) => {
      const { written, done } = runVerify({
        hosts: [`127.0.0.1:${port}`],
        expectFingerprint: fp,
        minDays: 20,
      });
      assertEquals((await done).dataHandles.length, 2);
      assertEquals(written[`cert-127-0-0-1-${port}`].verdict, "ok");
    });
  });
});

Deno.test("verify refuses with the cause for each non-ok verdict, after writing the results", async () => {
  await withTempDir(async (dir) => {
    await makeCert(dir, "a", 10);
    const other = await makeCert(dir, "b", 90);
    await withServer(dir, "a", [], async (port) => {
      const host = `127.0.0.1:${port}`;
      for (
        const [inputs, verdict] of <[Inputs, string][]> [
          [{ hosts: [host], expectFingerprint: other }, "other-certificate"],
          [{ hosts: [host], minDays: 20 }, "expiring"],
        ]
      ) {
        const { written, done } = runVerify(inputs);
        const err = await assertRejects(() => done, Error);
        const r = written[`cert-127-0-0-1-${port}`];
        assertEquals(r.verdict, verdict);
        assertEquals(err.message, r.cause);
      }
    });
    const closed = freePort();
    const { written, done } = runVerify({ hosts: [`127.0.0.1:${closed}`] });
    const err = await assertRejects(() => done, Error);
    const r = written[`cert-127-0-0-1-${closed}`];
    assertEquals(r.verdict, "unreachable");
    assertEquals(err.message, r.error);
  });
});

Deno.test("verify refuses a host list that is not exactly one host", async () => {
  for (const hosts of [["a:1", "b:2"], []]) {
    const { written, done } = runVerify({ hosts });
    await assertRejects(() => done, Error, "exactly one host");
    assertEquals(written, {});
  }
});
