// Runs in the browser under e2e_test.go: subscribes to a track published
// by a Go client through the relay, and publishes one that a Go client
// subscribes to. Posts its findings to /result.
import { Session } from "../src/index.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();

async function main() {
  const result: Record<string, unknown> = { ua: navigator.userAgent };
  try {
    const cfg = await (await fetch("/config")).json();
    const hash = Uint8Array.from((cfg.certHash as string).match(/../g)!.map((h) => parseInt(h, 16)));
    let published: () => void = () => {};
    const publishedDone = new Promise<void>((r) => (published = r));

    const s = await Session.connect({
      url: cfg.url,
      serverCertificateHashes: [hash],
      handler: {
        onSubscribe: async (req) => {
          const w = await req.accept({ properties: [{ type: 0x30, int: 1 }] });
          for (let g = 0; g < 3; g++) {
            const sg = w.openSubgroup(g, 0, { endOfGroup: true });
            for (let o = 0; o < 5; o++) await sg.writeObject({ id: o, status: 0, payload: enc.encode(`browser ${g}/${o}`) });
            await sg.close();
          }
          // A subgroup with no Objects must not open a stream.
          await w.openSubgroup(3, 0).close();
          await w.close(0x2, "done");
          result.publishedTo = req.track.name;
          published();
        },
      },
    });
    result.connected = true;
    await s.publishNamespace(["e2e", "browser"]);

    const sub = await s.subscribe({ namespace: ["e2e", "go"], name: "clock" }, { locationFilter: { type: 1, startGroup: 1 } });
    const groups: { group: number; objects: string[] }[] = [];
    for (let i = 0; i < 3; i++) {
      const g = await sub.nextSubgroup();
      if (!g) throw new Error("subscription ended early");
      const objects: string[] = [];
      for await (const o of g) objects.push(dec.decode(o.payload));
      groups.push({ group: g.header.group, objects });
    }
    result.received = groups;
    sub.unsubscribe();

    const f = await s.fetch({ namespace: ["e2e", "go"], name: "history" }, { locationFilter: { type: 4, startGroup: 2 ** 33 + 10, startObject: 0, endGroupDelta: 2, endObject: 0 } });
    if (f.endLocation.group !== 2 ** 33 + 12) throw new Error(`fetch end ${JSON.stringify(f.endLocation)}`);
    const fetched: string[] = [];
    for await (const o of f) {
      if (o.range) fetched.push(`range ${o.group}/${o.object}`);
      else {
        const ts = o.properties?.find((p) => p.type === 0x10)?.int;
        fetched.push(`${o.group}/${o.object}:${dec.decode(o.payload)}${ts === undefined ? "" : ` ts=${ts}`}`);
      }
    }
    result.fetched = fetched;

    await publishedDone;
    await fetch("/go-done"); // wait until the Go subscriber has everything
    s.close();
    result.ok = true;
  } catch (e) {
    result.error = String((e as Error)?.stack ?? e);
  }
  await fetch("/result", { method: "POST", body: JSON.stringify(result) });
  window.close();
}

void main();
