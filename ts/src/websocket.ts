// The subset of WebTransport a Session uses, and an implementation over a
// WebSocket speaking the frames of moqt's Go transport/ws package.

/** A bidirectional stream, as WebTransport gives one. */
export interface BidiStream {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
}

/** What a Session needs from its transport; WebTransport provides it. */
export interface Transport {
  readonly ready: Promise<unknown>;
  readonly closed: Promise<{ closeCode?: number; reason?: string }>;
  readonly datagrams: { readonly readable: ReadableStream<Uint8Array>; readonly writable: WritableStream<Uint8Array> };
  readonly incomingBidirectionalStreams: ReadableStream<BidiStream>;
  readonly incomingUnidirectionalStreams: ReadableStream<ReadableStream<Uint8Array>>;
  createBidirectionalStream(): Promise<BidiStream>;
  createUnidirectionalStream(opts?: { sendOrder?: number }): Promise<WritableStream<Uint8Array>>;
  close(info?: { closeCode?: number; reason?: string }): void;
}

/** The WebSocket subprotocol of moqt over WebSocket. */
export const WebSocketSubprotocol = "moqt-22+ws";

const Frame = { Stream: 0x08, StreamFin: 0x09, ResetStream: 0x04, StopSending: 0x05, Datagram: 0x30, Close: 0x1d } as const;

/** Bounds a STREAM frame, so an urgent stream waits for at most one chunk of another. */
const MaxChunk = 16 << 10;
/** Sending pauses while the socket has this much unsent: data handed to it can no longer be reordered or dropped. */
const HighWater = 64 << 10;
/** Streams opened without a sendOrder (control and requests) go first. */
const Urgent = Number.MAX_SAFE_INTEGER;
/** Datagrams beyond this many queued are dropped, as the network might. */
const MaxQueuedDatagrams = 64;
const MaxUnread = 64 << 20;

/** @internal QUIC variable-length integers (RFC 9000 Section 16). */
export function appendVarint(out: number[], v: number) {
  if (!Number.isSafeInteger(v) || v < 0) throw new RangeError(`invalid varint ${v}`);
  if (v < 0x40) out.push(v);
  else if (v < 0x4000) out.push(0x40 | (v >> 8), v & 0xff);
  else if (v < 0x40000000) out.push(0x80 | (v >>> 24), (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  else {
    const hi = Math.floor(v / 2 ** 32);
    const lo = v >>> 0;
    out.push(0xc0 | (hi >>> 24), (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff, lo >>> 24, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
  }
}

/** @internal Returns the value and the offset after it. */
export function readVarint(b: Uint8Array, off: number): [number, number] {
  if (off >= b.length) throw new Error("malformed frame");
  const n = 1 << (b[off] >> 6);
  if (off + n > b.length) throw new Error("malformed frame");
  let v = b[off] & 0x3f;
  for (let i = 1; i < n; i++) v = v * 256 + b[off + i];
  if (!Number.isSafeInteger(v)) throw new Error("varint exceeds 2^53");
  return [v, off + n];
}

/** @internal */
export interface ParsedFrame {
  type: number;
  id: number;
  fin: boolean;
  code: number;
  data: Uint8Array;
}

/** @internal */
export function encodeFrame(type: number, fields: number[], data?: Uint8Array): Uint8Array<ArrayBuffer> {
  const head: number[] = [];
  appendVarint(head, type);
  for (const f of fields) appendVarint(head, f);
  const out = new Uint8Array(head.length + (data?.length ?? 0));
  out.set(head);
  if (data) out.set(data, head.length);
  return out;
}

/** @internal */
export function parseFrame(b: Uint8Array): ParsedFrame {
  let [type, off] = readVarint(b, 0);
  const f: ParsedFrame = { type, id: 0, fin: false, code: 0, data: new Uint8Array() };
  switch (type) {
    case Frame.Stream:
    case Frame.StreamFin:
      f.type = Frame.Stream;
      f.fin = type === Frame.StreamFin;
      [f.id, off] = readVarint(b, off);
      f.data = b.subarray(off);
      break;
    case Frame.ResetStream:
    case Frame.StopSending:
      [f.id, off] = readVarint(b, off);
      [f.code, off] = readVarint(b, off);
      if (off !== b.length) throw new Error("malformed frame");
      break;
    case Frame.Datagram:
      f.data = b.subarray(off);
      break;
    case Frame.Close:
      [f.code, off] = readVarint(b, off);
      f.data = b.subarray(off);
      break;
    default:
      throw new Error(`unknown frame type 0x${type.toString(16)}`);
  }
  return f;
}

/** The stream error code carried by an abort or cancel reason. */
function errorCode(reason: unknown): number {
  const c = (reason as { streamErrorCode?: unknown } | undefined)?.streamErrorCode;
  return typeof c === "number" && Number.isSafeInteger(c) && c >= 0 ? c : 0;
}

/** A stream error the way WebTransport reports one. */
export class StreamResetError extends Error {
  readonly streamErrorCode: number;
  constructor(code: number, message: string) {
    super(message);
    this.name = "WebTransportError";
    this.streamErrorCode = code;
  }
}

interface Chunk {
  data: Uint8Array;
  fin: boolean;
  done: () => void;
}

class SendState {
  queue: Chunk[] = [];
  finished = false;
  constructor(readonly id: number, public sendOrder: number) {}
}

class RecvState {
  controller!: ReadableStreamDefaultController<Uint8Array>;
  finished = false;
  unread = 0;
}

/**
 * A WebTransport-like session over a WebSocket, for browsers without
 * (working) WebTransport. Streams share one TCP connection, so a lost packet
 * delays all of them; higher sendOrder streams are sent first.
 */
export class WebSocketTransport implements Transport {
  readonly ready: Promise<void>;
  readonly closed: Promise<{ closeCode: number; reason: string }>;
  readonly datagrams: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };
  readonly incomingBidirectionalStreams: ReadableStream<BidiStream>;
  readonly incomingUnidirectionalStreams: ReadableStream<ReadableStream<Uint8Array>>;

  private ws: WebSocket;
  private sends = new Map<number, SendState>();
  private recvs = new Map<number, RecvState>();
  private ctrl: Uint8Array<ArrayBuffer>[] = [];
  private outDatagrams: Uint8Array<ArrayBuffer>[] = [];
  private nextBidi = 0;
  private nextUni = 0;
  private nextPeer = [0, 0];
  private unread = 0;
  private ended = false;
  private pumpTimer?: ReturnType<typeof setTimeout>;
  private bidiCtl!: ReadableStreamDefaultController<BidiStream>;
  private uniCtl!: ReadableStreamDefaultController<ReadableStream<Uint8Array>>;
  private dgramCtl!: ReadableStreamDefaultController<Uint8Array>;
  private resolveClosed!: (i: { closeCode: number; reason: string }) => void;
  private rejectClosed!: (e: Error) => void;

  /** Connects to a wss:// URL. */
  constructor(url: string) {
    this.closed = new Promise((resolve, reject) => {
      this.resolveClosed = resolve;
      this.rejectClosed = reject;
    });
    this.closed.catch(() => {});
    this.incomingBidirectionalStreams = new ReadableStream({ start: (c) => void (this.bidiCtl = c) });
    this.incomingUnidirectionalStreams = new ReadableStream({ start: (c) => void (this.uniCtl = c) });
    this.datagrams = {
      readable: new ReadableStream({ start: (c) => void (this.dgramCtl = c) }, { highWaterMark: 256 }),
      writable: new WritableStream({
        write: (d) => {
          if (this.ended) throw new Error("session closed");
          if (this.outDatagrams.length < MaxQueuedDatagrams) {
            this.outDatagrams.push(encodeFrame(Frame.Datagram, [], d));
            this.pump();
          }
        },
      }),
    };
    this.ws = new WebSocket(url, WebSocketSubprotocol);
    this.ws.binaryType = "arraybuffer";
    this.ready = new Promise((resolve, reject) => {
      this.ws.onopen = () => {
        if (this.ws.protocol !== WebSocketSubprotocol) {
          const e = new Error(`the server does not speak ${WebSocketSubprotocol}`);
          reject(e);
          this.terminate(e);
          return;
        }
        resolve();
      };
      this.ws.onerror = () => {
        const e = new Error(`WebSocket connection to ${url} failed`);
        reject(e);
        this.terminate(e);
      };
      this.ws.onclose = (ev) => {
        const e = new Error(`WebSocket closed (${ev.code})${ev.reason ? ": " + ev.reason : ""}`);
        reject(e);
        this.terminate(e);
      };
    });
    this.ready.catch(() => {});
    this.ws.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return this.fail("text message");
      try {
        this.handle(parseFrame(new Uint8Array(ev.data)));
      } catch (e) {
        this.fail(e instanceof Error ? e.message : String(e));
      }
      this.pump();
    };
  }

  close(info: { closeCode?: number; reason?: string } = {}) {
    if (this.ended) return;
    const code = info.closeCode ?? 0;
    const reason = info.reason ?? "";
    try {
      this.ws.send(encodeFrame(Frame.Close, [code], new TextEncoder().encode(reason).subarray(0, 1024)));
    } catch {
      // not open
    }
    this.terminate(undefined, { closeCode: code, reason }, 1000);
  }

  async createBidirectionalStream(): Promise<BidiStream> {
    await this.ready;
    const id = this.nextBidi++ * 4;
    return { readable: this.openRecv(id), writable: this.openSend(id, Urgent) };
  }

  async createUnidirectionalStream(opts: { sendOrder?: number } = {}): Promise<WritableStream<Uint8Array>> {
    await this.ready;
    return this.openSend(this.nextUni++ * 4 + 2, opts.sendOrder ?? Urgent);
  }

  private fail(reason: string) {
    // MOQT's PROTOCOL_VIOLATION: the frames carry MOQT.
    this.close({ closeCode: 0x3, reason });
  }

  /** Ends the session: cleanly with info, or with err. */
  private terminate(err?: Error, info?: { closeCode: number; reason: string }, wsCode?: number) {
    if (this.ended) return;
    this.ended = true;
    clearTimeout(this.pumpTimer);
    const e = err ?? new Error(`session closed (${info?.closeCode}): ${info?.reason}`);
    for (const s of this.sends.values()) for (const c of s.queue) c.done();
    this.sends.clear();
    for (const r of this.recvs.values()) {
      try {
        r.controller.error(e);
      } catch {
        // already closed
      }
    }
    this.recvs.clear();
    for (const c of [this.bidiCtl, this.uniCtl, this.dgramCtl]) {
      try {
        c.close();
      } catch {
        // already closed
      }
    }
    if (info) this.resolveClosed(info);
    else this.rejectClosed(e);
    if (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN) this.ws.close(wsCode);
  }

  private openSend(id: number, sendOrder: number): WritableStream<Uint8Array> {
    const s = new SendState(id, sendOrder);
    this.sends.set(id, s);
    let signal: AbortSignal | undefined;
    const reset = (reason: unknown) => {
      if (s.finished) return;
      s.finished = true;
      for (const c of s.queue) c.done();
      s.queue = [];
      this.sends.delete(id);
      if (this.ended) return;
      this.ctrl.push(encodeFrame(Frame.ResetStream, [id, errorCode(reason)]));
      this.pump();
    };
    const enqueue = (data: Uint8Array, fin: boolean) =>
      new Promise<void>((resolve, reject) => {
        if (this.ended) return reject(new Error("session closed"));
        if (s.finished) return reject(new StreamResetError(0, "stream reset"));
        s.queue.push({ data, fin, done: resolve });
        this.pump();
      });
    return new WritableStream<Uint8Array>({
      start: (controller) => {
        // An abort must drop queued data at once, not after the write in
        // flight drains.
        signal = (controller as { signal?: AbortSignal }).signal;
        signal?.addEventListener("abort", () => reset(signal?.reason));
      },
      write: (chunk) => enqueue(chunk, false),
      close: () => enqueue(new Uint8Array(), true),
      abort: (reason) => reset(reason),
    });
  }

  private openRecv(id: number): ReadableStream<Uint8Array> {
    const r = new RecvState();
    this.recvs.set(id, r);
    return new ReadableStream<Uint8Array>({
      start: (c) => void (r.controller = c),
      pull: () => {
        this.unread -= r.unread;
        r.unread = 0;
      },
      cancel: (reason) => {
        if (r.finished) return;
        r.finished = true;
        this.unread -= r.unread;
        this.recvs.delete(id);
        if (this.ended) return;
        this.ctrl.push(encodeFrame(Frame.StopSending, [id, errorCode(reason)]));
        this.pump();
      },
    });
  }

  private handle(f: ParsedFrame) {
    if (this.ended) return;
    switch (f.type) {
      case Frame.Datagram:
        if ((this.dgramCtl.desiredSize ?? 0) > 0) this.dgramCtl.enqueue(f.data);
        return;
      case Frame.Close:
        this.terminate(undefined, { closeCode: f.code, reason: new TextDecoder().decode(f.data) }, 1000);
        return;
      case Frame.StopSending: {
        const s = this.sends.get(f.id);
        if (!s) return;
        s.finished = true;
        for (const c of s.queue) c.done();
        s.queue = [];
        this.sends.delete(f.id);
        this.ctrl.push(encodeFrame(Frame.ResetStream, [f.id, f.code]));
        this.pump();
        return;
      }
    }
    const r = this.recvs.get(f.id) ?? this.peerStream(f.id);
    if (!r || r.finished) return;
    if (f.type === Frame.ResetStream) {
      r.finished = true;
      this.unread -= r.unread;
      this.recvs.delete(f.id);
      r.controller.error(new StreamResetError(f.code, `stream reset by peer (${f.code})`));
      return;
    }
    if (f.data.length > 0) {
      r.controller.enqueue(f.data);
      r.unread += f.data.length;
      this.unread += f.data.length;
      if (this.unread > MaxUnread) return this.fail("too much unread data");
    }
    if (f.fin) {
      r.finished = true;
      this.recvs.delete(f.id);
      r.controller.close();
    }
  }

  /** Opens the peer's stream id, and as in QUIC every lower one of its kind. */
  private peerStream(id: number): RecvState | undefined {
    if ((id & 1) === 0) return undefined; // ours, already finished
    const uni = (id & 2) !== 0;
    const kind = uni ? 1 : 0;
    const count = Math.floor(id / 4);
    let r: RecvState | undefined;
    for (; this.nextPeer[kind] <= count; this.nextPeer[kind]++) {
      const sid = this.nextPeer[kind] * 4 + (uni ? 3 : 1);
      const readable = this.openRecv(sid);
      r = this.recvs.get(sid);
      if (uni) this.uniCtl.enqueue(readable);
      else this.bidiCtl.enqueue({ readable, writable: this.openSend(sid, Urgent) });
    }
    return r;
  }

  /** Sends frames while the socket keeps up: control, datagrams, then the stream with the highest sendOrder. */
  private pump() {
    if (this.ended || this.ws.readyState !== WebSocket.OPEN) return;
    while (this.ws.bufferedAmount < HighWater) {
      const f = this.ctrl.shift() ?? this.outDatagrams.shift() ?? this.nextStreamFrame();
      if (!f) return;
      this.ws.send(f);
    }
    // WebSocket has no drain event. Hidden tabs throttle timers, so writes
    // and incoming frames pump too.
    this.pumpTimer ??= setTimeout(() => {
      this.pumpTimer = undefined;
      this.pump();
    }, 5);
  }

  private nextStreamFrame(): Uint8Array<ArrayBuffer> | undefined {
    let best: SendState | undefined;
    for (const s of this.sends.values()) {
      if (s.queue.length > 0 && (!best || s.sendOrder > best.sendOrder || (s.sendOrder === best.sendOrder && s.id < best.id))) best = s;
    }
    if (!best) return undefined;
    const c = best.queue[0];
    const data = c.data.subarray(0, MaxChunk);
    c.data = c.data.subarray(data.length);
    const last = c.data.length === 0;
    const fin = last && c.fin;
    if (last) {
      best.queue.shift();
      c.done();
    }
    if (fin) {
      best.finished = true;
      this.sends.delete(best.id);
    }
    return encodeFrame(fin ? Frame.StreamFin : Frame.Stream, [best.id], data);
  }
}
