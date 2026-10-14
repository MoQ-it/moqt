import { afterEach, expect, test, vi } from "vitest";
import { Session } from "./session.ts";

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
