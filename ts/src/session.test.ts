import { afterEach, expect, test, vi } from "vitest";
import { Session } from "./session.ts";
import { encodeMessage, MsgType, StreamType, Writer } from "./wire.ts";

afterEach(() => vi.unstubAllGlobals());

test("connect gives up on a stalled WebTransport handshake", async () => {
  let closes = 0;
  vi.stubGlobal(
    "WebTransport",
    class {
      ready = new Promise(() => {});
      closed = new Promise(() => {});
      close() {
        closes++;
      }
    },
  );
  await expect(Session.connect({ url: "https://relay.test/moq", readyTimeoutMs: 20 })).rejects.toThrow("timed out opening a WebTransport session");
  expect(closes).toBe(1);
});

test("connect explains a missing WebTransport", async () => {
  vi.stubGlobal("WebTransport", undefined);
  await expect(Session.connect({ url: "https://relay.test/moq" })).rejects.toThrow("does not support WebTransport");
});

test("connect times out when the SETUP cannot be sent", async () => {
  const never = () => new ReadableStream<Uint8Array>();
  vi.stubGlobal(
    "WebTransport",
    class {
      ready = Promise.resolve();
      closed = new Promise(() => {});
      datagrams = { readable: never(), writable: new WritableStream() };
      incomingBidirectionalStreams = never();
      incomingUnidirectionalStreams = never();
      async createUnidirectionalStream() {
        return new WritableStream({ write: () => new Promise(() => {}) });
      }
      close() {}
    },
  );
  await expect(Session.connect({ url: "https://relay.test/moq", setupTimeoutMs: 20 })).rejects.toThrow("no SETUP");
});

test("openIncomingStreams counts incoming streams until they end", async () => {
  const enc = (bytes: Uint8Array, end: boolean) => new ReadableStream<Uint8Array>({ start: (c) => (c.enqueue(bytes), end && c.close()) });
  const padding = new Writer().varint(StreamType.Padding).finish();
  let push!: (s: ReadableStream<Uint8Array>) => void;
  const never = () => new ReadableStream<Uint8Array>();
  vi.stubGlobal(
    "WebTransport",
    class {
      ready = Promise.resolve();
      closed = new Promise(() => {});
      datagrams = { readable: never(), writable: new WritableStream() };
      incomingBidirectionalStreams = never();
      incomingUnidirectionalStreams = new ReadableStream({
        start(c) {
          c.enqueue(enc(encodeMessage({ type: MsgType.Setup, options: [] }), false));
          push = (s) => c.enqueue(s);
        },
      });
      async createUnidirectionalStream() {
        return new WritableStream();
      }
      close() {}
    },
  );
  const s = await Session.connect({ url: "https://relay.test/moq" });
  push(enc(padding, false)); // left open
  push(enc(padding, true)); // ends
  await new Promise((r) => setTimeout(r, 20));
  expect(s.openIncomingStreams()).toEqual({ control: 1, padding: 1 });
});
