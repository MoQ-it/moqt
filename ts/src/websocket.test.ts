import { afterEach, expect, test, vi } from "vitest";
import { openTransport, webTransportUsable } from "./session.ts";
import { appendVarint, encodeFrame, parseFrame, readVarint, WebSocketSubprotocol, WebSocketTransport } from "./websocket.ts";

afterEach(() => vi.unstubAllGlobals());

/** A WebSocket that records what is sent and lets the test play the server. */
class FakeSocket {
  static last: FakeSocket;
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 3;
  readyState = 0;
  protocol = "";
  binaryType = "blob";
  bufferedAmount = 0;
  sent: ReturnType<typeof parseFrame>[] = [];
  closedWith?: number;
  onopen?: () => void;
  onerror?: () => void;
  onclose?: (ev: { code: number; reason: string }) => void;
  onmessage?: (ev: { data: unknown }) => void;
  constructor(
    readonly url: string,
    readonly protocols: string,
  ) {
    FakeSocket.last = this;
  }
  open(protocol = WebSocketSubprotocol) {
    this.readyState = 1;
    this.protocol = protocol;
    this.onopen?.();
  }
  send(b: Uint8Array) {
    this.sent.push(parseFrame(new Uint8Array(b)));
  }
  close(code = 1005) {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.closedWith = code;
    this.onclose?.({ code, reason: "" });
  }
  deliver(b: Uint8Array) {
    this.onmessage?.({ data: b.slice().buffer });
  }
}

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

async function connected(): Promise<[WebSocketTransport, FakeSocket]> {
  vi.stubGlobal("WebSocket", FakeSocket);
  const t = new WebSocketTransport("wss://relay.test/moq");
  const ws = FakeSocket.last;
  ws.open();
  await t.ready;
  return [t, ws];
}

test("varints round-trip at every length", () => {
  for (const v of [0, 63, 64, 16383, 16384, 2 ** 30 - 1, 2 ** 30, 2 ** 53 - 1]) {
    const out: number[] = [];
    appendVarint(out, v);
    expect(out.length).toBe(v < 64 ? 1 : v < 16384 ? 2 : v < 2 ** 30 ? 4 : 8);
    expect(readVarint(new Uint8Array(out), 0)).toEqual([v, out.length]);
  }
  expect(() => parseFrame(new Uint8Array([0x04, 0x01]))).toThrow("malformed");
  expect(() => parseFrame(new Uint8Array([0x3f]))).toThrow("unknown frame");
});

test("frames match the Go encoding", () => {
  // STREAM with FIN on stream 2: type 0x09, id 0x02, data.
  expect([...encodeFrame(0x09, [2], new Uint8Array([7]))]).toEqual([0x09, 0x02, 0x07]);
  expect([...encodeFrame(0x04, [3, 0x12])]).toEqual([0x04, 0x03, 0x12]);
});

test("ready needs the moqt subprotocol", async () => {
  vi.stubGlobal("WebSocket", FakeSocket);
  const t = new WebSocketTransport("wss://relay.test/moq");
  expect(FakeSocket.last.protocols).toBe(WebSocketSubprotocol);
  FakeSocket.last.open("other");
  await expect(t.ready).rejects.toThrow("does not speak");
});

test("streams with a higher sendOrder are sent first", async () => {
  const [t, ws] = await connected();
  ws.bufferedAmount = 1 << 30; // hold everything back
  const low = (await t.createUnidirectionalStream({ sendOrder: 1 })).getWriter();
  const high = (await t.createUnidirectionalStream({ sendOrder: 9 })).getWriter();
  const lowDone = low.write(new Uint8Array(40 << 10));
  const highDone = high.write(new Uint8Array([1]));
  await tick();
  expect(ws.sent).toEqual([]);
  ws.bufferedAmount = 0;
  await Promise.all([lowDone, highDone]);
  expect(ws.sent.map((f) => f.id)).toEqual([6, 2, 2, 2]);
  // A stream opened without a sendOrder (control, requests) beats both.
  ws.bufferedAmount = 1 << 30;
  const ctrl = (await t.createUnidirectionalStream()).getWriter();
  const more = low.write(new Uint8Array(1));
  const ctrlDone = ctrl.write(new Uint8Array(1));
  await tick();
  ws.bufferedAmount = 0;
  await Promise.all([more, ctrlDone]);
  expect(ws.sent.slice(-2).map((f) => f.id)).toEqual([10, 2]);
  ws.sent.length = 4;
  expect(ws.sent.map((f) => f.data.length)).toEqual([1, 16 << 10, 16 << 10, 8 << 10]);
  await high.close();
  expect(ws.sent.at(-1)).toMatchObject({ type: 0x08, id: 6, fin: true });
});

test("an abort drops queued data and resets the stream", async () => {
  const [t, ws] = await connected();
  ws.bufferedAmount = 1 << 30;
  const w = (await t.createUnidirectionalStream()).getWriter();
  void w.write(new Uint8Array(100)).catch(() => {});
  await tick();
  await w.abort(Object.assign(new Error("x"), { streamErrorCode: 5 }));
  ws.bufferedAmount = 0;
  await tick(20);
  expect(ws.sent).toEqual([expect.objectContaining({ type: 0x04, id: 2, code: 5 })]);
});

test("incoming streams, resets, STOP_SENDING and close", async () => {
  const [t, ws] = await connected();
  // The server's second unidirectional stream implicitly opens its first.
  ws.deliver(encodeFrame(0x09, [7], new TextEncoder().encode("two")));
  ws.deliver(encodeFrame(0x08, [3], new TextEncoder().encode("one")));
  const uni = t.incomingUnidirectionalStreams.getReader();
  const first = (await uni.read()).value!.getReader();
  expect(new TextDecoder().decode((await first.read()).value)).toBe("one");
  ws.deliver(encodeFrame(0x04, [3, 9]));
  await expect(first.read()).rejects.toMatchObject({ streamErrorCode: 9 });
  const second = (await uni.read()).value!.getReader();
  expect(new TextDecoder().decode((await second.read()).value)).toBe("two");
  expect((await second.read()).done).toBe(true);

  // A cancelled reader asks the server to stop.
  ws.deliver(encodeFrame(0x08, [1], new Uint8Array([1])));
  const bidi = (await t.incomingBidirectionalStreams.getReader().read()).value!;
  await bidi.readable.cancel(Object.assign(new Error("x"), { streamErrorCode: 4 }));
  await tick();
  expect(ws.sent.at(-1)).toMatchObject({ type: 0x05, id: 1, code: 4 });

  // The server's STOP_SENDING is answered with a reset.
  const w = (await t.createUnidirectionalStream()).getWriter();
  await w.write(new Uint8Array([1]));
  ws.deliver(encodeFrame(0x05, [2, 6]));
  expect(ws.sent.at(-1)).toMatchObject({ type: 0x04, id: 2, code: 6 });

  ws.deliver(encodeFrame(0x30, [], new Uint8Array([42])));
  expect((await t.datagrams.readable.getReader().read()).value).toEqual(new Uint8Array([42]));

  ws.deliver(encodeFrame(0x1d, [0x10], new TextEncoder().encode("bye")));
  await expect(t.closed).resolves.toEqual({ closeCode: 0x10, reason: "bye" });
});

test("close sends CONNECTION_CLOSE", async () => {
  const [t, ws] = await connected();
  t.close({ closeCode: 2, reason: "done" });
  expect(ws.sent.at(-1)).toMatchObject({ type: 0x1d, code: 2 });
  expect(ws.closedWith).toBe(1000);
  await expect(t.closed).resolves.toEqual({ closeCode: 2, reason: "done" });
});

test("a lost connection rejects closed", async () => {
  const [t, ws] = await connected();
  const r = (await t.createUnidirectionalStream()).getWriter();
  ws.close(1006);
  await expect(t.closed).rejects.toThrow("1006");
  await expect(r.write(new Uint8Array([1]))).rejects.toThrow();
});

test("WebKit browsers are kept off WebTransport", () => {
  vi.stubGlobal("WebTransport", class {});
  for (const [ua, want] of [
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15", false],
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 26_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/140.0 Mobile/15E148 Safari/604.1", false],
    ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36", true],
    ["Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", true],
  ] as const) {
    vi.stubGlobal("navigator", { userAgent: ua });
    expect(webTransportUsable(), ua).toBe(want);
  }
  vi.stubGlobal("WebTransport", undefined);
  vi.stubGlobal("navigator", { userAgent: "Firefox/140.0" });
  expect(webTransportUsable()).toBe(false);
});

test("auto falls back to a WebSocket when WebTransport fails", async () => {
  vi.stubGlobal("WebSocket", FakeSocket);
  vi.stubGlobal(
    "WebTransport",
    class {
      ready = Promise.reject(new Error("UDP blocked"));
      closed = new Promise(() => {});
      close() {}
    },
  );
  const opening = openTransport({ url: "https://relay.test:4443/moq?x=1" }, 1000);
  await tick();
  expect(FakeSocket.last.url).toBe("wss://relay.test:4443/moq?x=1");
  FakeSocket.last.open();
  const [, kind] = await opening;
  expect(kind).toBe("websocket");
});

test("auto keeps WebTransport when it connects in time", async () => {
  vi.stubGlobal("WebSocket", FakeSocket);
  FakeSocket.last = undefined as unknown as FakeSocket;
  vi.stubGlobal(
    "WebTransport",
    class {
      ready = new Promise((r) => setTimeout(r, 10));
      closed = new Promise(() => {});
      close() {}
    },
  );
  const [, kind] = await openTransport({ url: "https://relay.test/moq", webSocketDelayMs: 200 }, 1000);
  expect(kind).toBe("webtransport");
  expect(FakeSocket.last).toBeUndefined();
});

test("a slow WebTransport is raced by a WebSocket, and the loser closed", async () => {
  vi.stubGlobal("WebSocket", FakeSocket);
  let closed = 0;
  vi.stubGlobal(
    "WebTransport",
    class {
      ready = new Promise(() => {});
      closed = new Promise(() => {});
      close() {
        closed++;
      }
    },
  );
  const opening = openTransport({ url: "https://relay.test/moq", webSocketDelayMs: 5 }, 1000);
  await tick(20);
  FakeSocket.last.open();
  expect((await opening)[1]).toBe("websocket");
  expect(closed).toBe(1);
});

test("websocket mode never tries WebTransport", async () => {
  vi.stubGlobal("WebSocket", FakeSocket);
  vi.stubGlobal("WebTransport", undefined);
  const opening = openTransport({ url: "https://relay.test/moq", transport: "websocket", webSocketUrl: "wss://ws.relay.test/moq" }, 1000);
  expect(FakeSocket.last.url).toBe("wss://ws.relay.test/moq");
  FakeSocket.last.open();
  expect((await opening)[1]).toBe("websocket");
  await expect(openTransport({ url: "https://relay.test/moq", transport: "webtransport" }, 1000)).rejects.toThrow("does not support WebTransport");
});
