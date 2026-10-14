// Wire encoding of draft-ietf-moq-transport-22, mirroring the Go package
// wire/v22. Integers are JS numbers (exact to 2^53); the few fields that
// need the full 64-bit range use bigint.

export const ALPN = "moqt-22";

// Session termination codes (Section 16.11.1).
export const SessionErrorCode = {
  NoError: 0x0,
  Internal: 0x1,
  Unauthorized: 0x2,
  ProtocolViolation: 0x3,
  InvalidRequestId: 0x4,
  DuplicateTrackAlias: 0x5,
  KeyValueFormatting: 0x6,
  InvalidPath: 0x8,
  ControlMessageTimeout: 0x11,
} as const;

// REQUEST_ERROR codes (Section 16.11.2).
export const RequestErrorCode = {
  Internal: 0x0,
  Unauthorized: 0x1,
  Timeout: 0x2,
  NotSupported: 0x3,
  GoingAway: 0x6,
  DoesNotExist: 0x10,
  Uninterested: 0x20,
  Redirect: 0x34,
} as const;

// PUBLISH_DONE status codes (Section 16.11.3).
export const PublishDoneCode = {
  InternalError: 0x0,
  Unauthorized: 0x1,
  TrackEnded: 0x2,
  GoingAway: 0x4,
  TooFarBehind: 0x5,
} as const;

// Stream reset codes (Section 16.11.4).
export const ResetCode = {
  InternalError: 0x0,
  Cancelled: 0x1,
  DeliveryTimeout: 0x2,
  SessionClosed: 0x3,
} as const;

/** A failure the spec says must close the session with `code`. */
export class SessionError extends Error {
  readonly code: number;
  constructor(code: number, reason: string) {
    super(reason);
    this.code = code;
    this.name = "SessionError";
  }
}

/** Thrown by Reader when the input ends early. */
export class ShortBuffer extends Error {
  constructor() {
    super("unexpected end of data");
    this.name = "ShortBuffer";
  }
}

export function protocolViolation(reason: string): SessionError {
  return new SessionError(SessionErrorCode.ProtocolViolation, reason);
}

// ---- variable-length integers (Section 8.1) ----

/** Number of bytes in a varint whose first byte is b0. */
export function varintSize(b0: number): number {
  return Math.clz32(~b0 & 0xff) - 24 + 1;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Growable byte buffer for encoding. */
export class Writer {
  private buf: Uint8Array;
  length = 0;

  constructor(capacity = 64) {
    this.buf = new Uint8Array(capacity);
  }

  private ensure(n: number) {
    if (this.length + n <= this.buf.length) return;
    const next = new Uint8Array(Math.max(this.buf.length * 2, this.length + n));
    next.set(this.buf.subarray(0, this.length));
    this.buf = next;
  }

  u8(v: number): this {
    this.ensure(1);
    this.buf[this.length++] = v & 0xff;
    return this;
  }

  u16(v: number): this {
    this.ensure(2);
    this.buf[this.length++] = (v >> 8) & 0xff;
    this.buf[this.length++] = v & 0xff;
    return this;
  }

  bytes(b: Uint8Array): this {
    this.ensure(b.length);
    this.buf.set(b, this.length);
    this.length += b.length;
    return this;
  }

  varint(v: number | bigint): this {
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v) || v < 0) throw new RangeError(`invalid varint ${v}`);
      if (v < 0x80) return this.u8(v);
      if (v < 0x4000) return this.u8(0x80 | (v >> 8)).u8(v);
      if (v < 0x200000) return this.u8(0xc0 | (v >> 16)).u8(v >> 8).u8(v);
      if (v < 0x10000000) return this.u8(0xe0 | (v >>> 24)).u8(v >> 16).u8(v >> 8).u8(v);
      v = BigInt(v);
    }
    if (v < 0n || v >= 1n << 64n) throw new RangeError(`invalid varint ${v}`);
    let n = 9;
    if (v < 1n << 56n) {
      n = 1;
      while (v >= 1n << BigInt(7 * n)) n++;
    }
    if (n === 9) {
      this.u8(0xff);
      for (let i = 7; i >= 0; i--) this.u8(Number((v >> BigInt(8 * i)) & 0xffn));
      return this;
    }
    const out: number[] = [];
    for (let i = n - 1; i >= 0; i--) out.push(Number((v >> BigInt(8 * i)) & 0xffn));
    out[0] |= (0xff00 >> (n - 1)) & 0xff;
    for (const b of out) this.u8(b);
    return this;
  }

  lengthPrefixed(b: Uint8Array): this {
    return this.varint(b.length).bytes(b);
  }

  string(s: string): this {
    return this.lengthPrefixed(encoder.encode(s));
  }

  finish(): Uint8Array {
    return this.buf.slice(0, this.length);
  }
}

/** Reads fields from a bounded buffer; throws ShortBuffer or SessionError. */
export class Reader {
  offset = 0;
  readonly buf: Uint8Array;
  constructor(buf: Uint8Array) {
    this.buf = buf;
  }

  get remaining(): number {
    return this.buf.length - this.offset;
  }

  u8(): number {
    if (this.offset >= this.buf.length) throw new ShortBuffer();
    return this.buf[this.offset++];
  }

  u16(): number {
    return (this.u8() << 8) | this.u8();
  }

  bytes(n: number): Uint8Array {
    if (n > this.remaining) throw new ShortBuffer();
    const b = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return b;
  }

  rest(): Uint8Array {
    return this.bytes(this.remaining);
  }

  varint64(): bigint {
    const b0 = this.u8();
    const n = varintSize(b0);
    if (n > this.remaining + 1) throw new ShortBuffer();
    let v = n === 9 ? 0n : BigInt(b0 & (0xff >> n));
    for (let i = 1; i < n; i++) v = (v << 8n) | BigInt(this.u8());
    return v;
  }

  /** A varint that must fit a JS number (2^53). */
  varint(): number {
    const b0 = this.buf[this.offset];
    if (b0 === undefined) throw new ShortBuffer();
    const n = varintSize(b0);
    if (n <= 7) {
      if (n > this.remaining) throw new ShortBuffer();
      let v = b0 & (0xff >> n);
      for (let i = 1; i < n; i++) v = v * 256 + this.buf[this.offset + i];
      this.offset += n;
      return v;
    }
    const v = this.varint64();
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw protocolViolation(`varint ${v} exceeds 2^53`);
    return Number(v);
  }

  lengthPrefixed(max: number, what: string): Uint8Array {
    const n = this.varint();
    if (n > max) throw protocolViolation(`${what} length ${n} exceeds ${max}`);
    return this.bytes(n);
  }

  string(max: number, what: string): string {
    return decoder.decode(this.lengthPrefixed(max, what));
  }

  sub(n: number): Reader {
    return new Reader(this.bytes(n));
  }
}

// ---- common structures (Section 8) ----

export const MaxNamespaceFields = 32;
export const MaxFullTrackNameBytes = 4096;
export const MaxReasonPhraseBytes = 1024;
export const MaxKeyValueBytes = 0xffff;

export interface Location {
  group: number;
  object: number;
}

/** Track Namespace tuple; fields are UTF-8 strings. */
export type Namespace = string[];

export interface FullTrackName {
  namespace: Namespace;
  name: string;
}

export function validateNamespace(ns: Namespace): void {
  if (ns.length > MaxNamespaceFields) throw protocolViolation(`namespace has ${ns.length} fields`);
  let total = 0;
  for (const f of ns) {
    const n = encoder.encode(f).length;
    if (n === 0) throw protocolViolation("empty namespace field");
    total += n;
  }
  if (total > MaxFullTrackNameBytes) throw protocolViolation("namespace too long");
}

export function hasPrefix(ns: Namespace, prefix: Namespace): boolean {
  return prefix.length <= ns.length && prefix.every((f, i) => ns[i] === f);
}

/** Renders a name per Section 8.8. */
export function renderName(s: string): string {
  let out = "";
  for (const c of encoder.encode(s)) {
    if ((c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39) || c === 0x5f) {
      out += String.fromCharCode(c);
    } else {
      out += "." + c.toString(16).padStart(2, "0");
    }
  }
  return out;
}

export function renderNamespace(ns: Namespace): string {
  return ns.map(renderName).join("-");
}

export function renderTrack(t: FullTrackName): string {
  return renderNamespace(t.namespace) + "--" + renderName(t.name);
}

/** A map key for a track; distinct names never collide. */
export function trackKey(t: FullTrackName): string {
  return JSON.stringify([t.namespace, t.name]);
}

export function writeNamespace(w: Writer, ns: Namespace): Writer {
  w.varint(ns.length);
  for (const f of ns) w.string(f);
  return w;
}

export function readNamespace(r: Reader): Namespace {
  const n = r.varint();
  if (n > MaxNamespaceFields) throw protocolViolation(`namespace has ${n} fields`);
  const ns: Namespace = [];
  for (let i = 0; i < n; i++) ns.push(r.string(MaxFullTrackNameBytes, "namespace field"));
  validateNamespace(ns);
  return ns;
}

function writeTrack(w: Writer, t: FullTrackName): Writer {
  return writeNamespace(w, t.namespace).string(t.name);
}

function readTrack(r: Reader): FullTrackName {
  const namespace = readNamespace(r);
  const name = r.string(MaxFullTrackNameBytes, "track name");
  return { namespace, name };
}

/** Key-Value-Pair (Section 8.3): even types carry `int`, odd types `bytes`. */
export interface KeyValue {
  type: number;
  int?: number;
  bytes?: Uint8Array;
}

export function writeKeyValues(w: Writer, kvs: KeyValue[]): Writer {
  const sorted = [...kvs].sort((a, b) => a.type - b.type);
  let prev = 0;
  for (const kv of sorted) {
    w.varint(kv.type - prev);
    prev = kv.type;
    if (kv.type % 2 === 0) w.varint(kv.int ?? 0);
    else w.lengthPrefixed(kv.bytes ?? new Uint8Array());
  }
  return w;
}

/** Reads Key-Value-Pairs until the reader is exhausted. */
export function readKeyValues(r: Reader): KeyValue[] {
  const kvs: KeyValue[] = [];
  let type = 0;
  while (r.remaining > 0) {
    type += r.varint();
    if (type % 2 === 0) kvs.push({ type, int: r.varint() });
    else kvs.push({ type, bytes: r.lengthPrefixed(MaxKeyValueBytes, "key-value") });
  }
  return kvs;
}

/** Authorization Token (Section 8.9). */
export const AliasType = { Delete: 0, Register: 1, UseAlias: 2, UseValue: 3 } as const;

export interface Token {
  aliasType: number;
  alias?: number;
  type?: number;
  value?: Uint8Array;
}

export function encodeToken(t: Token): Uint8Array {
  const w = new Writer().varint(t.aliasType);
  if (t.aliasType !== AliasType.UseValue) w.varint(t.alias ?? 0);
  if (t.aliasType === AliasType.Register || t.aliasType === AliasType.UseValue) {
    w.varint(t.type ?? 0).bytes(t.value ?? new Uint8Array());
  }
  return w.finish();
}

export function decodeToken(b: Uint8Array): Token {
  const r = new Reader(b);
  const t: Token = { aliasType: r.varint() };
  if (t.aliasType > AliasType.UseValue) throw new SessionError(SessionErrorCode.KeyValueFormatting, "token alias type");
  if (t.aliasType !== AliasType.UseValue) t.alias = r.varint();
  if (t.aliasType === AliasType.Register || t.aliasType === AliasType.UseValue) {
    t.type = r.varint();
    t.value = r.rest();
  } else if (r.remaining > 0) {
    throw new SessionError(SessionErrorCode.KeyValueFormatting, "trailing token bytes");
  }
  return t;
}

// ---- message parameters (Section 9.20) ----

export const Param = {
  ObjectDeliveryTimeout: 0x02,
  AuthorizationToken: 0x03,
  RendezvousTimeout: 0x04,
  SubgroupDeliveryTimeout: 0x06,
  Expires: 0x08,
  LargestObject: 0x09,
  FillTimeout: 0x0a,
  Forward: 0x10,
  SubscriberPriority: 0x20,
  LocationFilter: 0x21,
  GroupOrder: 0x22,
  FillParameters: 0x23,
  SubgroupFilter: 0x25,
  ObjectIdFilter: 0x26,
  PriorityFilter: 0x27,
  ObjectPropertyFilter: 0x28,
  TrackPropertyFilter: 0x29,
  NewGroupRequest: 0x32,
  TrackNamespacePrefix: 0x34,
  IncludeProperties: 0x35,
} as const;

export const FilterType = {
  None: 0,
  RelativeStart: 1,
  AbsoluteStart: 2,
  AbsoluteStartGroupEnd: 3,
  AbsoluteRange: 4,
  NextObject: 5,
} as const;

export interface LocationFilter {
  type: number;
  startGroup?: number;
  startObject?: number;
  endGroupDelta?: number;
  endObject?: number;
}

export interface Range {
  start: number;
  end?: number; // undefined: open-ended (last range only)
}

export interface RangeFilter {
  setId: number;
  propertyType?: number;
  ranges: Range[];
}

export interface Params {
  objectDeliveryTimeout?: number;
  authorizationTokens?: Token[];
  rendezvousTimeout?: number;
  subgroupDeliveryTimeout?: number;
  expires?: number;
  largestObject?: Location;
  fillTimeout?: number;
  forward?: number;
  subscriberPriority?: number;
  locationFilter?: LocationFilter;
  groupOrder?: number;
  fillParameters?: Params;
  subgroupFilters?: RangeFilter[];
  objectIdFilters?: RangeFilter[];
  priorityFilters?: RangeFilter[];
  objectPropertyFilters?: RangeFilter[];
  trackPropertyFilters?: RangeFilter[];
  newGroupRequest?: number;
  trackNamespacePrefix?: Namespace;
  includeProperties?: number;
}

type ParamEntry = [type: number, write: (w: Writer) => void];

function paramEntries(p: Params): ParamEntry[] {
  const e: ParamEntry[] = [];
  const v = (type: number, x: number | undefined) => x !== undefined && e.push([type, (w) => w.varint(x)]);
  const u8 = (type: number, x: number | undefined) => x !== undefined && e.push([type, (w) => w.u8(x)]);
  const rf = (type: number, fs: RangeFilter[] | undefined, prop: boolean) =>
    fs?.forEach((f) => e.push([type, (w) => writeRangeFilter(w, f, prop)]));
  v(Param.ObjectDeliveryTimeout, p.objectDeliveryTimeout);
  p.authorizationTokens?.forEach((t) => e.push([Param.AuthorizationToken, (w) => w.lengthPrefixed(encodeToken(t))]));
  v(Param.RendezvousTimeout, p.rendezvousTimeout);
  v(Param.SubgroupDeliveryTimeout, p.subgroupDeliveryTimeout);
  v(Param.Expires, p.expires);
  if (p.largestObject) {
    const l = p.largestObject;
    e.push([Param.LargestObject, (w) => w.varint(l.group).varint(l.object)]);
  }
  v(Param.FillTimeout, p.fillTimeout);
  u8(Param.Forward, p.forward);
  u8(Param.SubscriberPriority, p.subscriberPriority);
  if (p.locationFilter) {
    const f = p.locationFilter;
    e.push([Param.LocationFilter, (w) => writeLocationFilter(w, f)]);
  }
  u8(Param.GroupOrder, p.groupOrder);
  if (p.fillParameters) {
    const inner = p.fillParameters;
    e.push([Param.FillParameters, (w) => w.lengthPrefixed(writeParamValues(new Writer(), paramEntries(inner)).finish())]);
  }
  rf(Param.SubgroupFilter, p.subgroupFilters, false);
  rf(Param.ObjectIdFilter, p.objectIdFilters, false);
  rf(Param.PriorityFilter, p.priorityFilters, false);
  rf(Param.ObjectPropertyFilter, p.objectPropertyFilters, true);
  rf(Param.TrackPropertyFilter, p.trackPropertyFilters, true);
  v(Param.NewGroupRequest, p.newGroupRequest);
  if (p.trackNamespacePrefix) {
    const ns = p.trackNamespacePrefix;
    e.push([Param.TrackNamespacePrefix, (w) => writeNamespace(w, ns)]);
  }
  u8(Param.IncludeProperties, p.includeProperties);
  return e;
}

function writeParamValues(w: Writer, entries: ParamEntry[]): Writer {
  let prev = 0;
  for (const [type, write] of entries) {
    w.varint(type - prev);
    prev = type;
    write(w);
  }
  return w;
}

export function writeParams(w: Writer, p: Params = {}): Writer {
  const entries = paramEntries(p);
  return writeParamValues(w.varint(entries.length), entries);
}

function writeLocationFilter(w: Writer, f: LocationFilter) {
  w.varint(f.type);
  if (f.type === FilterType.RelativeStart) w.varint(f.startGroup ?? 0);
  if (f.type >= FilterType.AbsoluteStart && f.type <= FilterType.AbsoluteRange) w.varint(f.startGroup ?? 0).varint(f.startObject ?? 0);
  if (f.type === FilterType.AbsoluteStartGroupEnd || f.type === FilterType.AbsoluteRange) w.varint(f.endGroupDelta ?? 0);
  if (f.type === FilterType.AbsoluteRange) w.varint(f.endObject ?? 0);
}

function writeRangeFilter(w: Writer, f: RangeFilter, prop: boolean) {
  if (f.ranges.length === 0) {
    w.varint(0);
    return;
  }
  const body = new Writer().u8(f.setId);
  if (prop) body.varint(f.propertyType ?? 0);
  let prevEnd = 0;
  f.ranges.forEach((r, i) => {
    if (r.start < prevEnd) throw new RangeError("ranges must ascend");
    if (r.end === undefined && i !== f.ranges.length - 1) throw new RangeError("only the last range may be open");
    body.varint(r.start - prevEnd);
    if (r.end !== undefined) {
      body.varint(r.end - r.start);
      prevEnd = r.end;
    }
  });
  w.lengthPrefixed(body.finish());
}

const repeatable = new Set<number>([
  Param.AuthorizationToken,
  Param.SubgroupFilter,
  Param.ObjectIdFilter,
  Param.PriorityFilter,
  Param.ObjectPropertyFilter,
  Param.TrackPropertyFilter,
]);

function readParamValues(r: Reader, p: Params, more: (i: number) => boolean): Set<number> {
  const seen = new Set<number>();
  let type = 0;
  for (let i = 0; more(i); i++) {
    const delta = r.varint();
    type += delta;
    if (i > 0 && delta === 0 && !repeatable.has(type)) throw protocolViolation(`duplicate parameter 0x${type.toString(16)}`);
    seen.add(type);
    switch (type) {
      case Param.ObjectDeliveryTimeout: p.objectDeliveryTimeout = r.varint(); break;
      case Param.AuthorizationToken:
        (p.authorizationTokens ??= []).push(decodeToken(r.lengthPrefixed(MaxKeyValueBytes, "token")));
        break;
      case Param.RendezvousTimeout: p.rendezvousTimeout = r.varint(); break;
      case Param.SubgroupDeliveryTimeout: p.subgroupDeliveryTimeout = r.varint(); break;
      case Param.Expires: p.expires = r.varint(); break;
      case Param.LargestObject: p.largestObject = { group: r.varint(), object: r.varint() }; break;
      case Param.FillTimeout: p.fillTimeout = r.varint(); break;
      case Param.Forward: {
        const v = r.u8();
        if (v > 1) throw protocolViolation(`FORWARD ${v}`);
        p.forward = v;
        break;
      }
      case Param.SubscriberPriority: p.subscriberPriority = r.u8(); break;
      case Param.LocationFilter: p.locationFilter = readLocationFilter(r); break;
      case Param.GroupOrder: {
        const v = r.u8();
        if (v !== 1 && v !== 2) throw protocolViolation(`GROUP_ORDER ${v}`);
        p.groupOrder = v;
        break;
      }
      case Param.FillParameters: {
        const sub = r.sub(r.varint());
        const inner: Params = {};
        readParamValues(sub, inner, () => sub.remaining > 0);
        p.fillParameters = inner;
        break;
      }
      case Param.SubgroupFilter: (p.subgroupFilters ??= []).push(readRangeFilter(r, false)); break;
      case Param.ObjectIdFilter: (p.objectIdFilters ??= []).push(readRangeFilter(r, false)); break;
      case Param.PriorityFilter: (p.priorityFilters ??= []).push(readRangeFilter(r, false)); break;
      case Param.ObjectPropertyFilter: (p.objectPropertyFilters ??= []).push(readRangeFilter(r, true)); break;
      case Param.TrackPropertyFilter: (p.trackPropertyFilters ??= []).push(readRangeFilter(r, true)); break;
      case Param.NewGroupRequest: p.newGroupRequest = r.varint(); break;
      case Param.TrackNamespacePrefix: p.trackNamespacePrefix = readNamespace(r); break;
      case Param.IncludeProperties: {
        const v = r.u8();
        if (v > 1) throw protocolViolation(`INCLUDE_PROPERTIES ${v}`);
        p.includeProperties = v;
        break;
      }
      default:
        throw protocolViolation(`unknown parameter 0x${type.toString(16)}`);
    }
  }
  return seen;
}

function readParams(r: Reader, allowed: readonly number[], msg: string): Params {
  const n = r.varint();
  const p: Params = {};
  for (const t of readParamValues(r, p, (i) => i < n)) {
    if (!allowed.includes(t)) throw protocolViolation(`parameter 0x${t.toString(16)} not allowed in ${msg}`);
  }
  return p;
}

function readLocationFilter(r: Reader): LocationFilter {
  const f: LocationFilter = { type: r.varint() };
  switch (f.type) {
    case FilterType.None:
    case FilterType.NextObject:
      break;
    case FilterType.RelativeStart:
      f.startGroup = r.varint();
      break;
    case FilterType.AbsoluteStart:
      f.startGroup = r.varint();
      f.startObject = r.varint();
      break;
    case FilterType.AbsoluteStartGroupEnd:
      f.startGroup = r.varint();
      f.startObject = r.varint();
      f.endGroupDelta = r.varint();
      break;
    case FilterType.AbsoluteRange:
      f.startGroup = r.varint();
      f.startObject = r.varint();
      f.endGroupDelta = r.varint();
      f.endObject = r.varint();
      break;
    default:
      throw protocolViolation(`location filter type ${f.type}`);
  }
  return f;
}

function readRangeFilter(r: Reader, prop: boolean): RangeFilter {
  const sub = r.sub(r.varint());
  const f: RangeFilter = { setId: 0, ranges: [] };
  if (sub.remaining === 0) return f;
  f.setId = sub.u8();
  if (prop) f.propertyType = sub.varint();
  let prevEnd = 0;
  while (sub.remaining > 0) {
    const start = prevEnd + sub.varint();
    if (sub.remaining === 0) {
      f.ranges.push({ start });
    } else {
      const end = start + sub.varint();
      f.ranges.push({ start, end });
      prevEnd = end;
    }
  }
  return f;
}

// Parameters allowed per message (Section 9).
const P = Param;
const allowedParams = {
  subscribe: [P.ObjectDeliveryTimeout, P.AuthorizationToken, P.RendezvousTimeout, P.SubgroupDeliveryTimeout, P.Forward,
    P.SubscriberPriority, P.LocationFilter, P.GroupOrder, P.FillParameters, P.SubgroupFilter, P.ObjectIdFilter,
    P.PriorityFilter, P.ObjectPropertyFilter, P.NewGroupRequest, P.IncludeProperties],
  subscribeOk: [P.Expires, P.LargestObject],
  publish: [P.ObjectDeliveryTimeout, P.AuthorizationToken, P.SubgroupDeliveryTimeout, P.Expires, P.LargestObject,
    P.Forward, P.SubscriberPriority, P.LocationFilter, P.GroupOrder],
  publishStateNotify: [P.LargestObject, P.Forward, P.LocationFilter],
  fetch: [P.AuthorizationToken, P.FillTimeout, P.SubscriberPriority, P.LocationFilter, P.GroupOrder, P.SubgroupFilter,
    P.ObjectIdFilter, P.PriorityFilter, P.ObjectPropertyFilter, P.IncludeProperties],
  fetchOk: [],
  trackStatus: [P.AuthorizationToken, P.IncludeProperties],
  namespaceRequest: [P.AuthorizationToken],
  subscribeTracks: [P.AuthorizationToken, P.Forward, P.GroupOrder, P.SubgroupFilter, P.ObjectIdFilter, P.PriorityFilter,
    P.ObjectPropertyFilter, P.TrackPropertyFilter, P.IncludeProperties],
  requestOk: [P.Expires, P.LargestObject],
  requestUpdate: [P.ObjectDeliveryTimeout, P.AuthorizationToken, P.SubgroupDeliveryTimeout, P.Forward,
    P.SubscriberPriority, P.LocationFilter, P.FillParameters, P.SubgroupFilter, P.ObjectIdFilter, P.PriorityFilter,
    P.ObjectPropertyFilter, P.TrackPropertyFilter, P.NewGroupRequest, P.TrackNamespacePrefix],
} as const;

// ---- control messages (Section 9) ----

export const MsgType = {
  RequestUpdate: 0x2,
  Subscribe: 0x3,
  SubscribeOk: 0x4,
  RequestError: 0x5,
  PublishNamespace: 0x6,
  RequestOk: 0x7,
  Namespace: 0x8,
  PublishDone: 0xb,
  TrackStatus: 0xd,
  NamespaceDone: 0xe,
  PublishSkipped: 0xf,
  Goaway: 0x10,
  Fetch: 0x16,
  FetchOk: 0x18,
  Publish: 0x1d,
  PublishStateNotify: 0x22,
  SubscribeNamespace: 0x50,
  SubscribeTracks: 0x51,
  Setup: 0x2f00,
} as const;

export const SetupOption = {
  Path: 0x01,
  AuthorizationToken: 0x03,
  MaxAuthTokenCacheSize: 0x04,
  Authority: 0x05,
  MaxFilterRanges: 0x06,
  Implementation: 0x07,
  MaxRequestUpdates: 0x08,
} as const;

export interface Redirect {
  connectUri: string;
  track: FullTrackName;
}

export type Message =
  | { type: typeof MsgType.Setup; options: KeyValue[] }
  | { type: typeof MsgType.Goaway; newSessionUri: string; timeout: number }
  | { type: typeof MsgType.RequestOk; params: Params; trackProperties: KeyValue[] }
  | { type: typeof MsgType.RequestError; code: number; retryInterval: number; reason: string; redirect?: Redirect }
  | { type: typeof MsgType.RequestUpdate; requestId: number; params: Params }
  | { type: typeof MsgType.Subscribe; requestId: number; track: FullTrackName; params: Params }
  | { type: typeof MsgType.SubscribeOk; trackAlias: number; params: Params; trackProperties: KeyValue[] }
  | { type: typeof MsgType.Publish; requestId: number; track: FullTrackName; trackAlias: number; params: Params; trackProperties: KeyValue[] }
  | { type: typeof MsgType.PublishDone; statusCode: number; streamCount: bigint; reason: string }
  | { type: typeof MsgType.PublishStateNotify; params: Params }
  | { type: typeof MsgType.Fetch; requestId: number; track: FullTrackName; params: Params }
  | { type: typeof MsgType.FetchOk; endOfTrack: boolean; endLocation: Location; params: Params; trackProperties: KeyValue[] }
  | { type: typeof MsgType.TrackStatus; requestId: number; track: FullTrackName; params: Params }
  | { type: typeof MsgType.PublishNamespace; requestId: number; prefix: Namespace; params: Params }
  | { type: typeof MsgType.SubscribeNamespace; requestId: number; prefix: Namespace; params: Params }
  | { type: typeof MsgType.SubscribeTracks; requestId: number; prefix: Namespace; params: Params }
  | { type: typeof MsgType.Namespace; suffix: Namespace }
  | { type: typeof MsgType.NamespaceDone; suffix: Namespace }
  | { type: typeof MsgType.PublishSkipped; suffix: Namespace; trackName: string };

/** The full 64-bit Stream Count meaning "unknown" (Section 9.9). */
export const StreamCountUnknown = (1n << 64n) - 1n;

const requestTypes = new Set<number>([MsgType.TrackStatus, MsgType.Subscribe, MsgType.Publish, MsgType.Fetch,
  MsgType.PublishNamespace, MsgType.SubscribeNamespace, MsgType.SubscribeTracks]);

/** Whether a message type may open a request stream (Section 6.3). */
export function isRequest(type: number): boolean {
  return requestTypes.has(type);
}

export function encodeMessage(m: Message): Uint8Array {
  const body = new Writer();
  switch (m.type) {
    case MsgType.Setup:
      writeKeyValues(body, m.options);
      break;
    case MsgType.Goaway:
      body.string(m.newSessionUri).varint(m.timeout);
      break;
    case MsgType.RequestOk:
      writeKeyValues(writeParams(body, m.params), m.trackProperties);
      break;
    case MsgType.RequestError:
      body.varint(m.code).varint(m.retryInterval).string(m.reason);
      if (m.redirect) writeTrack(body.string(m.redirect.connectUri), m.redirect.track);
      break;
    case MsgType.RequestUpdate:
      writeParams(body.varint(m.requestId), m.params);
      break;
    case MsgType.Subscribe:
    case MsgType.Fetch:
    case MsgType.TrackStatus:
      writeParams(writeTrack(body.varint(m.requestId), m.track), m.params);
      break;
    case MsgType.SubscribeOk:
      writeKeyValues(writeParams(body.varint(m.trackAlias), m.params), m.trackProperties);
      break;
    case MsgType.Publish:
      writeKeyValues(writeParams(writeTrack(body.varint(m.requestId), m.track).varint(m.trackAlias), m.params), m.trackProperties);
      break;
    case MsgType.PublishDone:
      body.varint(m.statusCode).varint(m.streamCount).string(m.reason);
      break;
    case MsgType.PublishStateNotify:
      writeParams(body, m.params);
      break;
    case MsgType.FetchOk:
      writeKeyValues(writeParams(body.u8(m.endOfTrack ? 1 : 0).varint(m.endLocation.group).varint(m.endLocation.object), m.params), m.trackProperties);
      break;
    case MsgType.PublishNamespace:
    case MsgType.SubscribeNamespace:
    case MsgType.SubscribeTracks:
      writeParams(writeNamespace(body.varint(m.requestId), m.prefix), m.params);
      break;
    case MsgType.Namespace:
    case MsgType.NamespaceDone:
      writeNamespace(body, m.suffix);
      break;
    case MsgType.PublishSkipped:
      writeNamespace(body, m.suffix).string(m.trackName);
      break;
  }
  if (body.length > 0xffff) throw new RangeError("message body exceeds 65535 bytes");
  return new Writer(body.length + 4).varint(m.type).u16(body.length).bytes(body.finish()).finish();
}

/** Decodes a message body; the type and length have already been read. */
export function parseMessage(type: number, body: Uint8Array): Message {
  const r = new Reader(body);
  let m: Message;
  try {
    m = decodeBody(type, r);
  } catch (e) {
    if (e instanceof ShortBuffer) throw protocolViolation(`message 0x${type.toString(16)} body too short`);
    throw e;
  }
  if (r.remaining > 0) throw protocolViolation(`message 0x${type.toString(16)} has ${r.remaining} trailing bytes`);
  return m;
}

function decodeBody(type: number, r: Reader): Message {
  const A = allowedParams;
  switch (type) {
    case MsgType.Setup:
      return { type, options: readKeyValues(r) };
    case MsgType.Goaway:
      return { type, newSessionUri: r.string(8192, "GOAWAY URI"), timeout: r.varint() };
    case MsgType.RequestOk:
      return { type, params: readParams(r, A.requestOk, "REQUEST_OK"), trackProperties: readKeyValues(r) };
    case MsgType.RequestError: {
      const code = r.varint();
      const retryInterval = r.varint();
      const reason = r.string(MaxReasonPhraseBytes, "reason");
      if (code !== RequestErrorCode.Redirect) return { type, code, retryInterval, reason };
      const connectUri = r.string(8192, "redirect URI");
      return { type, code, retryInterval, reason, redirect: { connectUri, track: readTrack(r) } };
    }
    case MsgType.RequestUpdate:
      return { type, requestId: r.varint(), params: readParams(r, A.requestUpdate, "REQUEST_UPDATE") };
    case MsgType.Subscribe:
      return { type, requestId: r.varint(), track: readTrack(r), params: readParams(r, A.subscribe, "SUBSCRIBE") };
    case MsgType.Fetch:
      return { type, requestId: r.varint(), track: readTrack(r), params: readParams(r, A.fetch, "FETCH") };
    case MsgType.TrackStatus:
      return { type, requestId: r.varint(), track: readTrack(r), params: readParams(r, A.trackStatus, "TRACK_STATUS") };
    case MsgType.SubscribeOk:
      return { type, trackAlias: r.varint(), params: readParams(r, A.subscribeOk, "SUBSCRIBE_OK"), trackProperties: readKeyValues(r) };
    case MsgType.Publish: {
      const requestId = r.varint();
      const track = readTrack(r);
      const trackAlias = r.varint();
      return { type, requestId, track, trackAlias, params: readParams(r, A.publish, "PUBLISH"), trackProperties: readKeyValues(r) };
    }
    case MsgType.PublishDone:
      return { type, statusCode: r.varint(), streamCount: r.varint64(), reason: r.string(MaxReasonPhraseBytes, "reason") };
    case MsgType.PublishStateNotify:
      return { type, params: readParams(r, A.publishStateNotify, "PUBLISH_STATE_NOTIFY") };
    case MsgType.FetchOk: {
      const eot = r.u8();
      if (eot > 1) throw protocolViolation(`FETCH_OK end of track ${eot}`);
      const endLocation = { group: r.varint(), object: r.varint() };
      return { type, endOfTrack: eot === 1, endLocation, params: readParams(r, A.fetchOk, "FETCH_OK"), trackProperties: readKeyValues(r) };
    }
    case MsgType.PublishNamespace:
    case MsgType.SubscribeNamespace:
      return { type, requestId: r.varint(), prefix: readNamespace(r), params: readParams(r, A.namespaceRequest, "namespace request") };
    case MsgType.SubscribeTracks:
      return { type, requestId: r.varint(), prefix: readNamespace(r), params: readParams(r, A.subscribeTracks, "SUBSCRIBE_TRACKS") };
    case MsgType.Namespace:
    case MsgType.NamespaceDone:
      return { type, suffix: readNamespace(r) };
    case MsgType.PublishSkipped:
      return { type, suffix: readNamespace(r), trackName: r.string(MaxFullTrackNameBytes, "track name") };
  }
  throw protocolViolation(`unknown message type 0x${type.toString(16)}`);
}

/** Decodes one whole control message (type, length, body). */
export function decodeMessage(b: Uint8Array): Message {
  const r = new Reader(b);
  const type = r.varint();
  const len = r.u16();
  const body = r.bytes(len);
  if (r.remaining > 0) throw protocolViolation("bytes after message");
  return parseMessage(type, body);
}

// ---- properties (Section 10) ----

export const Prop = {
  ObjectDeliveryTimeout: 0x02,
  MaxCacheDuration: 0x04,
  SubgroupDeliveryTimeout: 0x06,
  Immutable: 0x0b,
  DefaultPublisherPriority: 0x0e,
  DefaultPublisherGroupOrder: 0x22,
  DynamicGroups: 0x30,
  PriorGroupIdGap: 0x3c,
  PriorObjectIdGap: 0x3e,
} as const;

export interface TrackInfo {
  publisherPriority: number;
  groupOrder: number;
  dynamicGroups: boolean;
}

/** Finds a property, also looking inside Immutable Properties (Section 10.7). */
export function lookupProperty(props: KeyValue[], type: number): KeyValue | undefined {
  const direct = props.find((kv) => kv.type === type);
  if (direct) return direct;
  const imm = props.find((kv) => kv.type === Prop.Immutable);
  if (imm?.bytes) return readKeyValues(new Reader(imm.bytes)).find((kv) => kv.type === type);
  return undefined;
}

export function parseTrackInfo(props: KeyValue[]): TrackInfo {
  const info: TrackInfo = { publisherPriority: 128, groupOrder: 1, dynamicGroups: false };
  const prio = lookupProperty(props, Prop.DefaultPublisherPriority);
  if (prio) {
    if ((prio.int ?? 0) > 255) throw protocolViolation("publisher priority");
    info.publisherPriority = prio.int ?? 0;
  }
  const order = lookupProperty(props, Prop.DefaultPublisherGroupOrder);
  if (order) {
    if (order.int !== 1 && order.int !== 2) throw protocolViolation("group order");
    info.groupOrder = order.int;
  }
  const dyn = lookupProperty(props, Prop.DynamicGroups);
  if (dyn) {
    if ((dyn.int ?? 0) > 1) throw protocolViolation("dynamic groups");
    info.dynamicGroups = dyn.int === 1;
  }
  return info;
}

// ---- data plane (Section 11) ----

export const StreamType = { Fetch: 0x05, Setup: 0x2f00, Padding: 0x132b3e28 } as const;
export const DatagramPadding = 0x132b3e29;

export function isSubgroupStreamType(t: number): boolean {
  return t < 0x80 && (t & 0x10) !== 0;
}

export const ObjectStatus = { Normal: 0x0, EndOfGroup: 0x3, EndOfTrack: 0x4 } as const;

function validStatus(s: number): boolean {
  return s === ObjectStatus.Normal || s === ObjectStatus.EndOfGroup || s === ObjectStatus.EndOfTrack;
}

export const SubgroupIdMode = { Zero: 0, FirstObject: 1, Explicit: 2 } as const;

export interface SubgroupHeader {
  trackAlias: number;
  group: number;
  idMode: number;
  subgroupId: number; // with SubgroupIdMode.Explicit
  priority?: number; // undefined: inherit the track's publisher priority
  properties: boolean;
  endOfGroup: boolean;
  firstObject: boolean;
}

export function encodeSubgroupHeader(h: SubgroupHeader): Uint8Array {
  let flags = 0x10 | (h.idMode << 1);
  if (h.properties) flags |= 0x01;
  if (h.endOfGroup) flags |= 0x08;
  if (h.priority === undefined) flags |= 0x20;
  if (h.firstObject) flags |= 0x40;
  const w = new Writer().varint(flags).varint(h.trackAlias).varint(h.group);
  if (h.idMode === SubgroupIdMode.Explicit) w.varint(h.subgroupId);
  if (h.priority !== undefined) w.u8(h.priority);
  return w.finish();
}

/** Flags-derived part of a subgroup header; the rest is read by the session. */
export function subgroupHeaderFlags(type: number): Omit<SubgroupHeader, "trackAlias" | "group" | "subgroupId" | "priority"> & { hasPriority: boolean } {
  const idMode = (type & 0x06) >> 1;
  if (!isSubgroupStreamType(type) || idMode === 3) throw protocolViolation(`subgroup header type 0x${type.toString(16)}`);
  return {
    idMode,
    properties: (type & 0x01) !== 0,
    endOfGroup: (type & 0x08) !== 0,
    hasPriority: (type & 0x20) === 0,
    firstObject: (type & 0x40) !== 0,
  };
}

export interface MoqObject {
  id: number;
  properties?: KeyValue[];
  status: number;
  payload: Uint8Array;
}

/** Encodes the Objects of one subgroup stream, delta-coding Object IDs. */
export class SubgroupEncoder {
  private prev = -1;
  readonly header: SubgroupHeader;
  constructor(header: SubgroupHeader) {
    this.header = header;
  }

  encode(o: MoqObject, w = new Writer()): Writer {
    if (o.id <= this.prev) throw new RangeError("object IDs must increase");
    if (!validStatus(o.status) || (o.status !== ObjectStatus.Normal && (o.payload.length > 0 || o.properties?.length))) {
      throw new RangeError("non-Normal objects carry no payload or properties");
    }
    if (o.properties?.length && !this.header.properties) throw new RangeError("header does not carry properties");
    w.varint(this.prev < 0 ? o.id : o.id - this.prev - 1);
    this.prev = o.id;
    if (this.header.properties) w.lengthPrefixed(writeKeyValues(new Writer(), o.properties ?? []).finish());
    w.varint(o.payload.length);
    if (o.payload.length === 0) w.varint(o.status);
    else w.bytes(o.payload);
    return w;
  }
}

export interface Datagram {
  trackAlias: number;
  group: number;
  object: number;
  priority?: number;
  properties?: KeyValue[];
  endOfGroup?: boolean;
  status: number;
  payload: Uint8Array;
}

export function encodeDatagram(d: Datagram): Uint8Array {
  const statusForm = d.status !== ObjectStatus.Normal || d.payload.length === 0;
  if (d.status !== ObjectStatus.Normal && (d.payload.length > 0 || d.properties?.length || d.endOfGroup)) {
    throw new RangeError("non-Normal datagram carries no payload, properties or END_OF_GROUP");
  }
  if (d.endOfGroup && statusForm) throw new RangeError("empty datagram cannot set END_OF_GROUP");
  let flags = 0;
  if (d.properties?.length) flags |= 0x01;
  if (d.endOfGroup) flags |= 0x02;
  if (d.object === 0) flags |= 0x04;
  if (d.priority === undefined) flags |= 0x08;
  if (statusForm) flags |= 0x20;
  const w = new Writer().varint(flags).varint(d.trackAlias).varint(d.group);
  if (d.object !== 0) w.varint(d.object);
  if (d.priority !== undefined) w.u8(d.priority);
  if (d.properties?.length) w.lengthPrefixed(writeKeyValues(new Writer(), d.properties).finish());
  return statusForm ? w.varint(d.status).finish() : w.bytes(d.payload).finish();
}

/** Parses an OBJECT_DATAGRAM; returns undefined for padding. */
export function parseDatagram(b: Uint8Array): Datagram | undefined {
  const r = new Reader(b);
  try {
    const flags = r.varint();
    if (flags === DatagramPadding) return undefined;
    if (flags >= 0x80 || (flags & ~0x2f) !== 0 || (flags & 0x22) === 0x22) throw protocolViolation(`datagram type 0x${flags.toString(16)}`);
    const d: Datagram = { trackAlias: r.varint(), group: r.varint(), object: 0, status: ObjectStatus.Normal, payload: new Uint8Array() };
    if ((flags & 0x02) !== 0) d.endOfGroup = true;
    if ((flags & 0x04) === 0) d.object = r.varint();
    if ((flags & 0x08) === 0) d.priority = r.u8();
    if ((flags & 0x01) !== 0) {
      const n = r.varint();
      if (n === 0) throw protocolViolation("empty datagram properties");
      d.properties = readKeyValues(r.sub(n));
    }
    if ((flags & 0x20) !== 0) {
      d.status = r.varint();
      if (!validStatus(d.status)) throw protocolViolation(`object status ${d.status}`);
      if (d.status !== ObjectStatus.Normal && d.properties) throw protocolViolation("properties on non-Normal object");
      if (r.remaining > 0) throw protocolViolation("bytes after datagram status");
    } else {
      d.payload = r.rest();
    }
    return d;
  } catch (e) {
    if (e instanceof ShortBuffer) throw protocolViolation("truncated datagram");
    throw e;
  }
}
