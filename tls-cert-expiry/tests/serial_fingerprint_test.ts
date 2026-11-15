import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  model,
  parseX509Fields,
} from "../models/tls_cert_expiry.ts";

// Fixture x509_serial_fingerprint.txt is real output, captured on 2026-11-14 with
// OpenSSL 4.1.0 23 Oct 2026, from a throwaway self-signed certificate:
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out cert.pem -days 30 \
//     -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
//   openssl x509 -noout -enddate -serial -fingerprint -sha256 -in cert.pem
const FIXTURE = await Deno.readTextFile(
  new URL("./x509_serial_fingerprint.txt", import.meta.url),
);

Deno.test("parseX509Fields reads serial and fingerprint from real openssl output", () => {
  const f = parseX509Fields(FIXTURE);
  assertEquals(f.serial, "0D78E38136B2609795476C0932E8F24B87158310");
  assertEquals(
    f.fingerprintSha256,
    "686bac20c9e2788cf5007df8a9c0350d11dab0c70c643944be5b9a150b4c93f2",
  );
  assertEquals(f.notAfter, "Dec 14 20:09:47 2026 GMT");
});

Deno.test("parseX509Fields returns null serial and fingerprint when absent", () => {
  const f = parseX509Fields("notAfter=Dec 14 20:09:47 2026 GMT\n");
  assertEquals(f.serial, null);
  assertEquals(f.fingerprintSha256, null);
});

Deno.test("parseX509Fields normalises case: serial upper, fingerprint lower, older 'SHA256' label", () => {
  const f = parseX509Fields(
    "serial=0a1b\nSHA256 Fingerprint=AB:cd:EF:01\n",
  );
  assertEquals(f.serial, "0A1B");
  assertEquals(f.fingerprintSha256, "abcdef01");
});

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

async function runCheck(hosts: string[]) {
  const written: Record<string, Record<string, unknown>> = {};
  await model.methods.check.execute(
    { hosts, defaultPort: 443 },
    {
      globalArgs: {
        warnThresholdDays: 30,
        criticalThresholdDays: 7,
        timeoutSec: 10,
      },
      logger: { info: () => {} },
      writeResource: (_spec, name, data) => {
        written[name] = data;
        return Promise.resolve({ name });
      },
    },
  );
  return written;
}

Deno.test("check against a live openssl s_server reports the served serial and fingerprint", async () => {
  const dir = await Deno.makeTempDir();
  const port = freePort();
  const cert = `${dir}/cert.pem`;
  await openssl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    `${dir}/k.pem`,
    "-out",
    cert,
    "-days",
    "90",
    "-subj",
    "/CN=localhost",
  ]);
  const expected = await openssl([
    "x509",
    "-noout",
    "-serial",
    "-fingerprint",
    "-sha256",
    "-in",
    cert,
  ]);
  const serial = expected.match(/^serial=(.+)$/m)![1];
  const fp = expected.match(/Fingerprint=(.+)$/m)![1].replaceAll(":", "")
    .toLowerCase();

  const server = new Deno.Command("openssl", {
    args: [
      "s_server",
      "-accept",
      `127.0.0.1:${port}`,
      "-cert",
      cert,
      "-key",
      `${dir}/k.pem`,
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
    const res = await runCheck([`127.0.0.1:${port}`]);
    const r = res[`cert-127-0-0-1-${port}`];
    assertEquals(r.error, null);
    assertEquals(r.serial, serial);
    assertEquals(r.fingerprintSha256, fp);
    assertEquals(r.status, "ok");
  } finally {
    try {
      server.kill("SIGKILL");
    } catch { /* gone */ }
    await server.status;
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("check reports null serial and fingerprint when the probe fails", async () => {
  const port = freePort(); // nothing listens here any more
  const res = await runCheck([`127.0.0.1:${port}`]);
  const r = res[`cert-127-0-0-1-${port}`];
  assertEquals(r.status, "error");
  assertEquals(r.notAfter, null);
  assertEquals(r.serial, null);
  assertEquals(r.fingerprintSha256, null);
});

// Found on sh-live-5: a Pebble certificate has an empty subject, and the
// parse took the next line ("issuer=…") as the subject.
Deno.test("parseX509Fields: an empty subject stays empty, not the next line", () => {
  const text = [
    "notBefore=Nov 14 21:17:14 2026 GMT",
    "notAfter=Feb 12 21:17:13 2027 GMT",
    "subject=",
    "issuer=CN = Pebble Intermediate CA 5f5c50",
  ].join("\n");
  const f = parseX509Fields(text);
  assertEquals(f.subject, null);
  assertEquals(f.issuer, "CN = Pebble Intermediate CA 5f5c50");
});
