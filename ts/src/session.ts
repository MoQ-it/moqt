// A MOQT session over the browser WebTransport API, mirroring the Go
// moqt package.

import { EndOfStream, readSubgroupHeader, StreamReader, SubgroupDecoder } from "./stream.ts";
import {
  ALPN,
  AliasType,
  type Datagram,
  encodeDatagram,
  encodeMessage,
  encodeSubgroupHeader,
  encodeToken,
  type FullTrackName,
  isRequest,
  isSubgroupStreamType,
  type KeyValue,
  type Location,
  type Message,
  type MoqObject,
  MsgType,
  type Namespace,
  type Params,
  parseDatagram,
  parseTrackInfo,
  protocolViolation,
  PublishDoneCode,
  type Redirect,
  RequestErrorCode,
  ResetCode,
  SessionError,
  SessionErrorCode,
  SetupOption,
  StreamCountUnknown,
  StreamType,
  SubgroupEncoder,
  type SubgroupHeader,
  SubgroupIdMode,
  type TrackInfo,
  trackKey,
  validateNamespace,
  Writer,
} from "./wire.ts";

export const Implementation = "moqt-ts/0.1 (draft-22)";

const encoder = new TextEncoder();

/** A REQUEST_ERROR from the peer. */
export class RequestError extends Error {
  readonly code: number;
  readonly retryInterval: number;
  readonly redirect?: Redirect;
  constructor(code: number, reason: string, retryInterval = 0, redirect?: Redirect) {
    super(reason || `request rejected (0x${code.toString(16)})`);
    this.name = "RequestError";
    this.code = code;
    this.retryInterval = retryInterval;
    this.redirect = redirect;
  }
}

/** Requests the peer initiates; unhandled ones get NOT_SUPPORTED. */
export interface Handler {
  onSubscribe?(req: SubscribeRequest): void;
  onPublishNamespace?(req: PublishNamespaceRequest): void;
  onSubscribeNamespace?(req: SubscribeNamespaceRequest): void;
}

export interface ConnectOptions {
  /** https:// URL of the relay's WebTransport endpoint. */
  url: string;
  /** SHA-256 hashes of a self-signed server certificate (development). */
  serverCertificateHashes?: Uint8Array[];
  /** Sent as the AUTHORIZATION TOKEN setup option (USE_VALUE). */
  authorizationToken?: Uint8Array;
  authorizationTokenType?: number;
  setupOptions?: KeyValue[];
  handler?: Handler;
  /** How long the WebTransport handshake may take (default 10000ms). */
  readyTimeoutMs?: number;
  setupTimeoutMs?: number;
  /** How long a data stream with an unknown Track Alias waits (default 2000ms). */
  aliasWaitMs?: number;
}

/** Async FIFO with close. */
class Queue<T> {
  private items: T[] = [];
  private waiters: ((v: T | undefined) => void)[] = [];
  private closed = false;

  push(v: T): boolean {
    if (this.closed) return false;
    const w = this.waiters.shift();
    if (w) w(v);
    else this.items.push(v);
    return true;
  }

  get length(): number {
    return this.items.length;
  }

  close() {
    this.closed = true;
    for (const w of this.waiters) w(undefined);
    this.waiters = [];
  }

  next(): Promise<T | undefined> {
    if (this.items.length > 0) return Promise.resolve(this.items.shift());
    if (this.closed) return Promise.resolve(undefined);
    return new Promise((r) => this.waiters.push(r));
  }
}

function streamError(code: number): unknown {
  const WTE = (globalThis as { WebTransportError?: new (m: string, o: object) => unknown }).WebTransportError;
  try {
    if (WTE) return new WTE("moqt", { streamErrorCode: code });
  } catch {
    // fall through
  }
  return new Error(`moqt stream error ${code}`);
}

/** One bidirectional request stream. */
class RequestStream {
  readonly reader: StreamReader;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  constructor(readonly session: Session, stream: WebTransportBidirectionalStream) {
    this.reader = new StreamReader(stream.readable);
    this.writer = stream.writable.getWriter();
  }

  async send(m: Message): Promise<void> {
    await this.writer.write(encodeMessage(m));
  }

  /** Next message; undefined on a clean FIN. Decoding errors close the session. */
  async recv(): Promise<Message | undefined> {
    try {
      if (await this.reader.done()) return undefined;
      return await this.reader.message();
    } catch (e) {
      if (e instanceof SessionError) this.session.fail(e);
      if (e instanceof EndOfStream) {
        const err = protocolViolation("request stream ended inside a message");
        this.session.fail(err);
        throw err;
      }
      throw e;
    }
  }

  /** FIN: nothing more to send. */
  finish() {
    this.writer.close().catch(() => {});
  }

  /** Cancel the request in both directions (Section 6.4.2.3). */
  cancel(code: number = ResetCode.Cancelled) {
    this.writer.abort(streamError(code)).catch(() => {});
    this.reader.cancel(streamError(code));
  }

  async reject(code: number, reason: string) {
    await this.send({ type: MsgType.RequestError, code, retryInterval: 0, reason }).catch(() => {});
    this.finish();
  }
}

export class Session {
  readonly wt: WebTransport;
  readonly handler: Handler;
  peerSetup: KeyValue[] = [];
  /** Resolves with the peer's GOAWAY. */
  readonly goaway: Promise<{ newSessionUri: string; timeout: number }>;
  /** Resolves when the session ends. */
  readonly closed: Promise<SessionError | Error>;

  private ctrl!: WritableStreamDefaultWriter<Uint8Array>;
  private nextRequestId = 0;
  private nextTrackAlias = 0;
  private peerIds = new Set<number>();
  private subs = new Map<number, Subscription>();
  private aliasWaiters = new Map<number, (() => void)[]>();
  private gotControl = false;
  private resolveGoaway!: (g: { newSessionUri: string; timeout: number }) => void;
  private resolveClosed!: (e: SessionError | Error) => void;
  private resolveSetup!: () => void;
  private rejectSetup!: (e: Error) => void;
  private ended = false;
  private datagramWriter?: WritableStreamDefaultWriter<Uint8Array>;
  private readonly aliasWaitMs: number;

  private constructor(wt: WebTransport, opts: ConnectOptions) {
    this.wt = wt;
    this.handler = opts.handler ?? {};
    this.aliasWaitMs = opts.aliasWaitMs ?? 2000;
    this.goaway = new Promise((r) => (this.resolveGoaway = r));
    this.closed = new Promise((r) => (this.resolveClosed = r));
  }

  /** Connects, exchanges SETUP and returns the established session. */
  static async connect(opts: ConnectOptions): Promise<Session> {
    const wtOpts: WebTransportOptions & { protocols?: string[] } = { protocols: [ALPN] };
    if (opts.serverCertificateHashes) {
      wtOpts.serverCertificateHashes = opts.serverCertificateHashes.map((value) => ({ algorithm: "sha-256", value: value as BufferSource }));
    }
    if (typeof WebTransport === "undefined") throw new Error("this browser does not support WebTransport");
    const wt = new WebTransport(opts.url, wtOpts);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`timed out opening a WebTransport session to ${opts.url}`)), opts.readyTimeoutMs ?? 10000);
    });
    try {
      await Promise.race([wt.ready, expired]);
    } catch (e) {
      try {
        wt.close();
      } catch {
        // already closed
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
    const negotiated = (wt as { protocol?: string }).protocol;
    if (negotiated !== undefined && negotiated !== "" && negotiated !== ALPN) {
      wt.close({ closeCode: SessionErrorCode.ProtocolViolation, reason: "protocol" });
      throw new Error(`server negotiated ${negotiated}, not ${ALPN}`);
    }
    const s = new Session(wt, opts);
    await s.start(opts);
    return s;
  }

  private async start(opts: ConnectOptions) {
    const setupDone = new Promise<void>((resolve, reject) => {
      this.resolveSetup = resolve;
      this.rejectSetup = reject;
    });
    this.wt.closed.then(
      (info) => this.terminate(new Error(`session closed (${info.closeCode}): ${info.reason}`)),
      (e) => this.terminate(e instanceof Error ? e : new Error(String(e))),
    );
    const timeout = setTimeout(() => {
      this.close(SessionErrorCode.ControlMessageTimeout, "no SETUP");
      this.rejectSetup(new Error("timed out waiting for SETUP"));
    }, opts.setupTimeoutMs ?? 10000);
    void this.acceptUniStreams();
    void this.acceptRequests();
    void this.receiveDatagrams();
    try {
      await Promise.all([this.sendSetup(opts), setupDone]);
    } finally {
      clearTimeout(timeout);
    }
  }

  private async sendSetup(opts: ConnectOptions) {
    this.ctrl = (await this.wt.createUnidirectionalStream()).getWriter();
    const options: KeyValue[] = [{ type: SetupOption.Implementation, bytes: encoder.encode(Implementation) }, ...(opts.setupOptions ?? [])];
    if (opts.authorizationToken) {
      const token = encodeToken({ aliasType: AliasType.UseValue, type: opts.authorizationTokenType ?? 0, value: opts.authorizationToken });
      options.push({ type: SetupOption.AuthorizationToken, bytes: token });
    }
    await this.ctrl.write(encodeMessage({ type: MsgType.Setup, options }));
  }

  close(code: number = SessionErrorCode.NoError, reason = "") {
    if (!this.ended) {
      try {
        this.wt.close({ closeCode: code, reason });
      } catch {
        // already closed
      }
    }
    this.terminate(new SessionError(code, reason || "closed"));
  }

  /** Closes the session because of err (Section 12). */
  fail(err: unknown) {
    if (this.ended) return;
    const se = err instanceof SessionError ? err : new SessionError(SessionErrorCode.Internal, String(err));
    console.warn("moqt: closing session", se.code, se.message);
    this.close(se.code, se.message);
  }

  private terminate(err: Error) {
    if (this.ended) return;
    this.ended = true;
    this.rejectSetup?.(err);
    for (const sub of this.subs.values()) sub.finish(undefined, err);
    this.resolveClosed(err);
  }

  private takeRequestId(): number {
    const id = this.nextRequestId;
    this.nextRequestId += 2;
    return id;
  }

  private async acceptUniStreams() {
    const reader = this.wt.incomingUnidirectionalStreams.getReader();
    for (;;) {
      const { value, done } = await reader.read().catch(() => ({ value: undefined, done: true }));
      if (done || !value) return;
      void this.handleUniStream(value).catch((e) => {
        if (e instanceof SessionError) this.fail(e);
      });
    }
  }

  private async handleUniStream(stream: ReadableStream<Uint8Array>) {
    const r = new StreamReader(stream);
    let type: number;
    try {
      type = await r.varint();
    } catch {
      return; // reset before the type arrived
    }
    if (type === StreamType.Setup) return this.readControl(r);
    if (isSubgroupStreamType(type)) return this.handleSubgroup(r, type);
    if (type === StreamType.Padding) {
      while (!(await r.done())) await r.exact(1);
      return;
    }
    if (type === StreamType.Fetch) {
      await r.cancel(streamError(ResetCode.Cancelled));
      return;
    }
    this.fail(protocolViolation(`unknown stream type 0x${type.toString(16)}`));
  }

  private async readControl(r: StreamReader) {
    if (this.gotControl) return this.fail(protocolViolation("second control stream"));
    this.gotControl = true;
    const setup = await r.messageBody(MsgType.Setup);
    if (setup.type !== MsgType.Setup) return;
    this.peerSetup = setup.options;
    this.resolveSetup();
    for (;;) {
      let m: Message;
      try {
        m = await r.message();
      } catch (e) {
        if (e instanceof SessionError) return this.fail(e);
        if (e instanceof EndOfStream) return this.fail(protocolViolation("control stream closed"));
        return; // transport teardown
      }
      if (m.type !== MsgType.Goaway) return this.fail(protocolViolation(`message 0x${m.type.toString(16)} on control stream`));
      this.resolveGoaway({ newSessionUri: m.newSessionUri, timeout: m.timeout });
    }
  }

  private async handleSubgroup(r: StreamReader, type: number) {
    const header = await readSubgroupHeader(r, type);
    const sub = await this.waitSubscription(header.trackAlias);
    if (!sub) {
      await r.cancel(streamError(ResetCode.Cancelled));
      return;
    }
    sub.deliverSubgroup(new IncomingSubgroup(this, header, r));
  }

  private waitSubscription(alias: number): Promise<Subscription | undefined> {
    const sub = this.subs.get(alias);
    if (sub) return Promise.resolve(sub);
    return new Promise((resolve) => {
      const list = this.aliasWaiters.get(alias) ?? [];
      const timer = setTimeout(() => resolve(this.subs.get(alias)), this.aliasWaitMs);
      list.push(() => {
        clearTimeout(timer);
        resolve(this.subs.get(alias));
      });
      this.aliasWaiters.set(alias, list);
    });
  }

  /** @internal */
  registerAlias(alias: number, sub: Subscription) {
    if (this.subs.has(alias)) throw new SessionError(SessionErrorCode.DuplicateTrackAlias, `track alias ${alias}`);
    this.subs.set(alias, sub);
    for (const w of this.aliasWaiters.get(alias) ?? []) w();
    this.aliasWaiters.delete(alias);
  }

  /** @internal Forget a finished subscription after late Objects stop arriving. */
  releaseAlias(alias: number, sub: Subscription) {
    setTimeout(() => {
      if (this.subs.get(alias) === sub) this.subs.delete(alias);
    }, 30000);
  }

  private async receiveDatagrams() {
    const reader = this.wt.datagrams.readable.getReader();
    for (;;) {
      const { value, done } = await reader.read().catch(() => ({ value: undefined, done: true }));
      if (done || !value) return;
      let d: Datagram | undefined;
      try {
        d = parseDatagram(value);
      } catch (e) {
        return this.fail(e);
      }
      if (d) this.subs.get(d.trackAlias)?.deliverDatagram(d);
    }
  }

  /** @internal */
  async sendDatagram(b: Uint8Array) {
    this.datagramWriter ??= this.wt.datagrams.writable.getWriter();
    await this.datagramWriter.write(b);
  }

  private async acceptRequests() {
    const reader = this.wt.incomingBidirectionalStreams.getReader();
    for (;;) {
      const { value, done } = await reader.read().catch(() => ({ value: undefined, done: true }));
      if (done || !value) return;
      void this.handleRequest(new RequestStream(this, value)).catch(() => {});
    }
  }

  private async handleRequest(rs: RequestStream) {
    const m = await rs.recv();
    if (!m) return;
    if (!isRequest(m.type)) return this.fail(protocolViolation(`request stream starts with 0x${m.type.toString(16)}`));
    const id = (m as { requestId: number }).requestId;
    if (!this.checkPeerRequestId(id)) return;
    switch (m.type) {
      case MsgType.Subscribe:
        if (this.handler.onSubscribe) return this.handler.onSubscribe(new SubscribeRequest(this, rs, m.requestId, m.track, m.params));
        break;
      case MsgType.PublishNamespace:
        if (this.handler.onPublishNamespace) return this.handler.onPublishNamespace(new PublishNamespaceRequest(rs, m.prefix, m.params));
        break;
      case MsgType.SubscribeNamespace:
        if (this.handler.onSubscribeNamespace) return this.handler.onSubscribeNamespace(new SubscribeNamespaceRequest(rs, m.prefix, m.params));
        break;
    }
    await rs.reject(RequestErrorCode.NotSupported, "not supported");
  }

  /** @internal Section 6.4.2.1: server IDs are odd and never repeat. */
  checkPeerRequestId(id: number): boolean {
    if (id % 2 !== 1 || this.peerIds.has(id)) {
      this.fail(new SessionError(SessionErrorCode.InvalidRequestId, `request ID ${id}`));
      return false;
    }
    this.peerIds.add(id);
    return true;
  }

  private async openRequest(m: (id: number) => Message): Promise<[RequestStream, Message]> {
    const rs = new RequestStream(this, await this.wt.createBidirectionalStream());
    await rs.send(m(this.takeRequestId()));
    const resp = await rs.recv();
    if (!resp) throw new Error("request stream closed without a response");
    if (resp.type === MsgType.RequestError) {
      rs.finish();
      throw new RequestError(resp.code, resp.reason, resp.retryInterval, resp.redirect);
    }
    return [rs, resp];
  }

  /** Subscribes to a track and waits for SUBSCRIBE_OK. */
  async subscribe(track: FullTrackName, params: Params = {}): Promise<Subscription> {
    const [rs, ok] = await this.openRequest((requestId) => ({ type: MsgType.Subscribe, requestId, track, params }));
    if (ok.type !== MsgType.SubscribeOk) {
      const err = protocolViolation(`unexpected 0x${ok.type.toString(16)} answering SUBSCRIBE`);
      this.fail(err);
      throw err;
    }
    const sub = new Subscription(this, rs, track, ok.trackAlias, parseTrackInfo(ok.trackProperties), ok.trackProperties, ok.params.largestObject);
    try {
      this.registerAlias(ok.trackAlias, sub);
    } catch (e) {
      this.fail(e);
      throw e;
    }
    void sub.readResponses();
    return sub;
  }

  /** Advertises that this endpoint publishes tracks under prefix. */
  async publishNamespace(prefix: Namespace, params: Params = {}): Promise<PublishedNamespace> {
    validateNamespace(prefix);
    const [rs, ok] = await this.openRequest((requestId) => ({ type: MsgType.PublishNamespace, requestId, prefix, params }));
    if (ok.type !== MsgType.RequestOk) {
      const err = protocolViolation("unexpected PUBLISH_NAMESPACE response");
      this.fail(err);
      throw err;
    }
    return new PublishedNamespace(rs, prefix);
  }

  /** Asks for the namespaces under prefix and their changes. */
  async subscribeNamespace(prefix: Namespace, params: Params = {}): Promise<NamespaceSubscription> {
    validateNamespace(prefix);
    const [rs, ok] = await this.openRequest((requestId) => ({ type: MsgType.SubscribeNamespace, requestId, prefix, params }));
    if (ok.type !== MsgType.RequestOk) {
      const err = protocolViolation("unexpected SUBSCRIBE_NAMESPACE response");
      this.fail(err);
      throw err;
    }
    const ns = new NamespaceSubscription(this, rs, prefix);
    void ns.read();
    return ns;
  }

  /** @internal */
  allocTrackAlias(): number {
    return this.nextTrackAlias++;
  }

  /** @internal */
  async takeRequestIdForUpdate(): Promise<number> {
    return this.takeRequestId();
  }
}

/** A subgroup stream being received. */
export class IncomingSubgroup {
  readonly header: SubgroupHeader;
  private decoder: SubgroupDecoder;
  private firstId?: number;
  constructor(private session: Session, header: SubgroupHeader, private reader: StreamReader) {
    this.header = header;
    this.decoder = new SubgroupDecoder(reader, header);
  }

  /** Subgroup ID; with FirstObject mode, known after the first Object. */
  get subgroupId(): number | undefined {
    if (this.header.idMode === SubgroupIdMode.Zero) return 0;
    if (this.header.idMode === SubgroupIdMode.Explicit) return this.header.subgroupId;
    return this.firstId;
  }

  /** The next Object, or undefined when the subgroup is complete. */
  async next(): Promise<MoqObject | undefined> {
    try {
      const o = await this.decoder.next();
      if (o && this.firstId === undefined) this.firstId = o.id;
      return o;
    } catch (e) {
      if (e instanceof SessionError) this.session.fail(e);
      throw e;
    }
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<MoqObject> {
    for (let o = await this.next(); o; o = await this.next()) yield o;
  }

  /** STOP_SENDING: no longer interested in this subgroup. */
  cancel() {
    void this.reader.cancel(streamError(ResetCode.Cancelled));
  }
}

const lateStreamWaitMs = 2000;

/** The subscriber's side of a subscription. */
export class Subscription {
  readonly info: TrackInfo;
  private subgroups = new Queue<IncomingSubgroup>();
  private datagrams = new Queue<Datagram>();
  private updateWaiters: ((m: Message) => void)[] = [];
  private streamsSeen = 0;
  private streamArrived: () => void = () => {};
  private ended = false;
  private unsubscribed = false;
  /** PUBLISH_DONE, or the error that ended the subscription. */
  readonly done: Promise<{ statusCode: number; streamCount: bigint; reason: string } | Error>;
  private resolveDone!: (v: { statusCode: number; streamCount: bigint; reason: string } | Error) => void;
  /** Called with PUBLISH_STATE_NOTIFY parameters. */
  onStateNotify?: (p: Params) => void;

  constructor(
    private session: Session,
    private rs: RequestStream,
    readonly track: FullTrackName,
    readonly trackAlias: number,
    info: TrackInfo,
    readonly properties: KeyValue[],
    readonly largestObject?: Location,
  ) {
    this.info = info;
    this.done = new Promise((r) => (this.resolveDone = r));
  }

  /** @internal */
  async readResponses() {
    for (;;) {
      let m: Message | undefined;
      try {
        m = await this.rs.recv();
      } catch (e) {
        return this.finish(undefined, e instanceof Error ? e : new Error(String(e)));
      }
      if (!m) return this.finish(undefined, new Error("subscription stream closed without PUBLISH_DONE"));
      switch (m.type) {
        case MsgType.PublishDone:
          this.rs.finish();
          await this.awaitStreams(m.streamCount);
          return this.finish({ statusCode: m.statusCode, streamCount: m.streamCount, reason: m.reason });
        case MsgType.PublishStateNotify:
          this.onStateNotify?.(m.params);
          break;
        case MsgType.RequestOk:
        case MsgType.RequestError: {
          const w = this.updateWaiters.shift();
          if (!w) return this.session.fail(protocolViolation("response without a pending REQUEST_UPDATE"));
          w(m);
          break;
        }
        default:
          return this.session.fail(protocolViolation(`unexpected 0x${m.type.toString(16)} in subscription`));
      }
    }
  }

  // PUBLISH_DONE can overtake data streams; wait for its Stream Count.
  private async awaitStreams(count: bigint) {
    const deadline = Date.now() + lateStreamWaitMs;
    while (count === StreamCountUnknown || BigInt(this.streamsSeen) < count) {
      const left = deadline - Date.now();
      if (left <= 0) return;
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, left);
        this.streamArrived = () => {
          clearTimeout(t);
          resolve();
        };
      });
      if (count === StreamCountUnknown) continue;
    }
  }

  /** @internal */
  finish(result?: { statusCode: number; streamCount: bigint; reason: string }, err?: Error) {
    if (this.ended) return;
    this.ended = true;
    this.subgroups.close();
    this.datagrams.close();
    this.resolveDone(result ?? err ?? new Error("ended"));
    this.session.releaseAlias(this.trackAlias, this);
  }

  /** @internal */
  deliverSubgroup(g: IncomingSubgroup) {
    this.streamsSeen++;
    this.streamArrived();
    if (this.unsubscribed || this.subgroups.length >= 64 || !this.subgroups.push(g)) g.cancel();
  }

  /** @internal */
  deliverDatagram(d: Datagram) {
    if (this.datagrams.length < 256) this.datagrams.push(d);
  }

  /** The next subgroup stream; undefined once the subscription has ended. */
  nextSubgroup(): Promise<IncomingSubgroup | undefined> {
    return this.subgroups.next();
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<IncomingSubgroup> {
    for (let g = await this.nextSubgroup(); g; g = await this.nextSubgroup()) yield g;
  }

  /** The next Object sent as a datagram. */
  nextDatagram(): Promise<Datagram | undefined> {
    return this.datagrams.next();
  }

  /** REQUEST_UPDATE, e.g. { newGroupRequest: 0 } for a keyframe. */
  async update(params: Params): Promise<void> {
    const reply = new Promise<Message>((r) => this.updateWaiters.push(r));
    await this.rs.send({ type: MsgType.RequestUpdate, requestId: await this.session.takeRequestIdForUpdate(), params });
    const m = await reply;
    if (m.type === MsgType.RequestError) throw new RequestError(m.code, m.reason);
  }

  unsubscribe() {
    this.unsubscribed = true;
    this.finish(undefined, new Error("unsubscribed"));
    this.rs.cancel();
  }
}

/** An incoming SUBSCRIBE (the relay asking this endpoint for a track). */
export class SubscribeRequest {
  constructor(
    private session: Session,
    private rs: RequestStream,
    readonly requestId: number,
    readonly track: FullTrackName,
    readonly params: Params,
  ) {}

  reject(code: number, reason = ""): Promise<void> {
    return this.rs.reject(code, reason);
  }

  /** Answers SUBSCRIBE_OK and returns the writer for the track. */
  async accept(opts: { properties?: KeyValue[]; largestObject?: Location; expires?: number } = {}): Promise<TrackWriter> {
    const properties = opts.properties ?? [];
    const info = parseTrackInfo(properties);
    const alias = this.session.allocTrackAlias();
    await this.rs.send({ type: MsgType.SubscribeOk, trackAlias: alias, params: { largestObject: opts.largestObject, expires: opts.expires }, trackProperties: properties });
    const w = new TrackWriter(this.session, this.rs, this.track, alias, info, this.params);
    void w.readRequests();
    return w;
  }
}

export interface SubgroupOptions {
  priority?: number;
  properties?: boolean;
  endOfGroup?: boolean;
  firstObject?: boolean;
}

/** The publisher's side of a subscription. */
export class TrackWriter {
  private streams = 0n;
  private closed = false;
  private abort = new AbortController();
  private subscriberPriority?: number;
  forwarding = true;
  /** Called with each REQUEST_UPDATE's parameters (already acknowledged). */
  onUpdate?: (p: Params) => void;

  constructor(
    private session: Session,
    private rs: RequestStream,
    readonly track: FullTrackName,
    readonly trackAlias: number,
    readonly info: TrackInfo,
    params: Params,
  ) {
    this.apply(params);
  }

  /** Aborted when the subscriber cancels or the session ends. */
  get signal(): AbortSignal {
    return this.abort.signal;
  }

  private apply(p: Params) {
    if (p.subscriberPriority !== undefined) this.subscriberPriority = p.subscriberPriority;
    if (p.forward !== undefined) this.forwarding = p.forward === 1;
  }

  /** @internal */
  async readRequests() {
    for (;;) {
      let m: Message | undefined;
      try {
        m = await this.rs.recv();
      } catch {
        this.abort.abort(new Error("subscriber cancelled"));
        return;
      }
      if (!m) return; // FIN: no more REQUEST_UPDATEs, not a cancellation
      if (m.type !== MsgType.RequestUpdate) return this.session.fail(protocolViolation("unexpected message from subscriber"));
      if (!this.session.checkPeerRequestId(m.requestId)) return;
      this.apply(m.params);
      this.onUpdate?.(m.params);
      await this.rs.send({ type: MsgType.RequestOk, params: {}, trackProperties: [] }).catch(() => {});
    }
  }

  /** @internal Lower MOQT priority sends first; sendOrder is the reverse. */
  sendOrder(publisherPriority: number): number {
    return 255 - (this.subscriberPriority ?? publisherPriority);
  }

  /** @internal */
  countStream() {
    this.streams++;
  }

  /** Starts a subgroup; its stream opens with the first Object. */
  openSubgroup(group: number, subgroupId: number, opts: SubgroupOptions = {}): OutgoingSubgroup {
    const header: SubgroupHeader = {
      trackAlias: this.trackAlias,
      group,
      idMode: subgroupId === 0 ? SubgroupIdMode.Zero : SubgroupIdMode.Explicit,
      subgroupId,
      priority: opts.priority,
      properties: opts.properties ?? false,
      endOfGroup: opts.endOfGroup ?? false,
      firstObject: opts.firstObject ?? false,
    };
    return new OutgoingSubgroup(this.session, this, header, opts.priority ?? this.info.publisherPriority);
  }

  async writeDatagram(d: Omit<Datagram, "trackAlias">): Promise<void> {
    await this.session.sendDatagram(encodeDatagram({ ...d, trackAlias: this.trackAlias }));
  }

  /** PUBLISH_DONE; call after every subgroup has been closed or reset. */
  async close(statusCode: number = PublishDoneCode.TrackEnded, reason = ""): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.rs.send({ type: MsgType.PublishDone, statusCode, streamCount: this.streams, reason }).catch(() => {});
    this.rs.finish();
    this.abort.abort(new Error("publish done"));
  }
}

/** A subgroup stream being sent. */
export class OutgoingSubgroup {
  private writer?: WritableStreamDefaultWriter<Uint8Array>;
  private encoder: SubgroupEncoder;
  constructor(private session: Session, private track: TrackWriter, private header: SubgroupHeader, private priority: number) {
    this.encoder = new SubgroupEncoder(header);
  }

  async writeObject(o: MoqObject): Promise<void> {
    const w = new Writer();
    if (!this.writer) {
      const stream = await this.session.wt.createUnidirectionalStream({ sendOrder: this.track.sendOrder(this.priority) } as WebTransportSendStreamOptions);
      this.writer = stream.getWriter();
      this.track.countStream();
      w.bytes(encodeSubgroupHeader(this.header));
    }
    this.encoder.encode(o, w);
    await this.writer.write(w.finish());
  }

  /** FIN after the last Object. A subgroup with no Objects sends nothing. */
  async close(): Promise<void> {
    await this.writer?.close().catch(() => {});
  }

  /** Abandon the subgroup, e.g. on a delivery timeout. */
  reset(code: number = ResetCode.Cancelled) {
    this.writer?.abort(streamError(code)).catch(() => {});
  }
}

/** An accepted PUBLISH_NAMESPACE made by this endpoint. */
export class PublishedNamespace {
  constructor(private rs: RequestStream, readonly prefix: Namespace) {}
  withdraw() {
    this.rs.cancel();
  }
}

/** An incoming PUBLISH_NAMESPACE. */
export class PublishNamespaceRequest {
  constructor(private rs: RequestStream, readonly prefix: Namespace, readonly params: Params) {}
  reject(code: number, reason = "") {
    return this.rs.reject(code, reason);
  }
  async accept(): Promise<void> {
    await this.rs.send({ type: MsgType.RequestOk, params: {}, trackProperties: [] });
  }
}

export interface NamespaceEvent {
  suffix: Namespace;
  active: boolean;
}

/** NAMESPACE / NAMESPACE_DONE for a SUBSCRIBE_NAMESPACE. */
export class NamespaceSubscription {
  private events = new Queue<NamespaceEvent>();
  constructor(private session: Session, private rs: RequestStream, readonly prefix: Namespace) {}

  /** @internal */
  async read() {
    const active = new Map<string, Namespace>();
    try {
      for (;;) {
        const m = await this.rs.recv();
        if (!m) break;
        if (m.type === MsgType.Namespace) {
          const k = JSON.stringify(m.suffix);
          if (active.has(k)) continue;
          active.set(k, m.suffix);
          this.events.push({ suffix: m.suffix, active: true });
        } else if (m.type === MsgType.NamespaceDone) {
          const k = JSON.stringify(m.suffix);
          if (!active.delete(k)) return this.session.fail(protocolViolation("NAMESPACE_DONE before NAMESPACE"));
          this.events.push({ suffix: m.suffix, active: false });
        } else {
          return this.session.fail(protocolViolation("unexpected message on SUBSCRIBE_NAMESPACE stream"));
        }
      }
    } catch {
      // stream reset: every namespace ends (Section 4.2.2)
    } finally {
      for (const suffix of active.values()) this.events.push({ suffix, active: false });
      this.events.close();
    }
  }

  next(): Promise<NamespaceEvent | undefined> {
    return this.events.next();
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<NamespaceEvent> {
    for (let e = await this.next(); e; e = await this.next()) yield e;
  }

  cancel() {
    this.rs.cancel();
  }
}

/** An incoming SUBSCRIBE_NAMESPACE. */
export class SubscribeNamespaceRequest {
  constructor(private rs: RequestStream, readonly prefix: Namespace, readonly params: Params) {}
  reject(code: number, reason = "") {
    return this.rs.reject(code, reason);
  }
  async accept(): Promise<{ announce(s: Namespace): Promise<void>; withdraw(s: Namespace): Promise<void> }> {
    await this.rs.send({ type: MsgType.RequestOk, params: {}, trackProperties: [] });
    const active = new Set<string>();
    return {
      announce: async (suffix) => {
        if (active.has(JSON.stringify(suffix))) return;
        active.add(JSON.stringify(suffix));
        await this.rs.send({ type: MsgType.Namespace, suffix });
      },
      withdraw: async (suffix) => {
        if (!active.delete(JSON.stringify(suffix))) throw new Error("namespace was not announced");
        await this.rs.send({ type: MsgType.NamespaceDone, suffix });
      },
    };
  }
}

export { trackKey };
