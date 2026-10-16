import {
  type KeyValue,
  type Message,
  type MoqObject,
  type SubgroupHeader,
  ObjectStatus,
  parseMessage,
  protocolViolation,
  Reader,
  readKeyValues,
  subgroupHeaderFlags,
  varintSize,
} from "./wire.ts";

/** Upper bounds on peer-chosen lengths, as in the Go implementation. */
export const MaxObjectPayload = 16 << 20;
export const MaxObjectProperties = 256 << 10;

/** Buffered reader over a WebTransport (or any) byte stream. */
export class StreamReader {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private buf = new Uint8Array(0);
  private off = 0;
  private eof = false;
  private ended = false;
  /** @internal Called once the stream has ended: FIN read, reset, or cancelled. */
  onEnd?: () => void;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader();
  }

  private end() {
    if (this.ended) return;
    this.ended = true;
    this.onEnd?.();
  }

  private get buffered(): number {
    return this.buf.length - this.off;
  }

  /** Ensures n bytes are buffered; false if the stream ends first. */
  private async fill(n: number): Promise<boolean> {
    while (this.buffered < n) {
      if (this.eof) return false;
      let r: ReadableStreamReadResult<Uint8Array>;
      try {
        r = await this.reader.read();
      } catch (e) {
        this.end();
        throw e;
      }
      const { value, done } = r;
      if (done) {
        this.eof = true;
        this.end();
        return this.buffered >= n;
      }
      if (this.off > 0 || this.buf.length === 0) {
        const rest = this.buf.subarray(this.off);
        const next = new Uint8Array(rest.length + value.length);
        next.set(rest);
        next.set(value, rest.length);
        this.buf = next;
        this.off = 0;
      } else {
        const next = new Uint8Array(this.buf.length + value.length);
        next.set(this.buf);
        next.set(value, this.buf.length);
        this.buf = next;
      }
    }
    return true;
  }

  /** True when the stream ended cleanly with nothing left to read. */
  async done(): Promise<boolean> {
    return !(await this.fill(1));
  }

  /** Reads n bytes; throws if the stream ends first. */
  async exact(n: number): Promise<Uint8Array> {
    if (!(await this.fill(n))) throw new EndOfStream();
    const b = this.buf.slice(this.off, this.off + n);
    this.off += n;
    return b;
  }

  async u8(): Promise<number> {
    return (await this.exact(1))[0];
  }

  async varint(): Promise<number> {
    if (!(await this.fill(1))) throw new EndOfStream();
    const n = varintSize(this.buf[this.off]);
    return new Reader(await this.exact(n)).varint();
  }

  /** Reads one control message. */
  async message(): Promise<Message> {
    const type = await this.varint();
    return this.messageBody(type);
  }

  /** Reads the length and body of a message whose type was already read. */
  async messageBody(type: number): Promise<Message> {
    const len = new Reader(await this.exact(2)).u16();
    return parseMessage(type, await this.exact(len));
  }

  /** STOP_SENDING / cancel. */
  async cancel(reason?: unknown): Promise<void> {
    this.end();
    await this.reader.cancel(reason).catch(() => {});
  }
}

/** The stream ended (FIN) where more data was required. */
export class EndOfStream extends Error {
  constructor() {
    super("stream ended");
    this.name = "EndOfStream";
  }
}

/** Reads the rest of a SUBGROUP_HEADER after its type. */
export async function readSubgroupHeader(r: StreamReader, type: number): Promise<SubgroupHeader> {
  const f = subgroupHeaderFlags(type);
  const h: SubgroupHeader = {
    trackAlias: await r.varint(),
    group: await r.varint(),
    idMode: f.idMode,
    subgroupId: 0,
    properties: f.properties,
    endOfGroup: f.endOfGroup,
    firstObject: f.firstObject,
  };
  if (h.idMode === 2) h.subgroupId = await r.varint();
  if (f.hasPriority) h.priority = await r.u8();
  return h;
}

/** Decodes the Objects of a subgroup stream. */
export class SubgroupDecoder {
  private prev = -1;
  private r: StreamReader;
  readonly header: SubgroupHeader;
  constructor(r: StreamReader, header: SubgroupHeader) {
    this.r = r;
    this.header = header;
  }

  /** The next Object, or undefined at the clean end of the subgroup. */
  async next(): Promise<MoqObject | undefined> {
    if (await this.r.done()) return undefined;
    try {
      const delta = await this.r.varint();
      const id = this.prev < 0 ? delta : this.prev + delta + 1;
      this.prev = id;
      let properties: KeyValue[] | undefined;
      if (this.header.properties) {
        const n = await this.r.varint();
        if (n > MaxObjectProperties) throw protocolViolation(`object properties of ${n} bytes`);
        properties = readKeyValues(new Reader(await this.r.exact(n)));
      }
      const len = await this.r.varint();
      if (len === 0) {
        const status = await this.r.varint();
        if (status !== ObjectStatus.Normal && status !== ObjectStatus.EndOfGroup && status !== ObjectStatus.EndOfTrack) {
          throw protocolViolation(`object status ${status}`);
        }
        if (status !== ObjectStatus.Normal && properties?.length) throw protocolViolation("properties on non-Normal object");
        return { id, properties, status, payload: new Uint8Array() };
      }
      if (len > MaxObjectPayload) throw protocolViolation(`object payload of ${len} bytes`);
      return { id, properties, status: ObjectStatus.Normal, payload: await this.r.exact(len) };
    } catch (e) {
      if (e instanceof EndOfStream) throw protocolViolation("stream ended inside an object");
      throw e;
    }
  }
}

/** End of Range kinds on a fetch stream (Table 8); 0 is an Object. */
export const FetchRange = { Object: 0, NonExistent: 0x8c, Unknown: 0x10c, TimedOut: 0x20c } as const;

/** One fetch stream entry: an Object, or an End of Range marker when range is set. */
export interface FetchObject {
  range: number;
  group: number;
  object: number;
  /** The Object was sent as a datagram and has no Subgroup. */
  datagram: boolean;
  subgroupId: number;
  priority: number;
  properties?: KeyValue[];
  payload: Uint8Array;
}

/** Decodes the entries after a FETCH_HEADER (Section 11.4.1). */
export class FetchDecoder {
  private started = false;
  private haveObject = false;
  private group = 0;
  private obj = 0;
  private subgroup = 0;
  private priority = 0;
  constructor(
    private r: StreamReader,
    private descending = false,
  ) {}

  /** The next entry, or undefined at the clean end of the stream. */
  async next(): Promise<FetchObject | undefined> {
    if (await this.r.done()) return undefined;
    try {
      return await this.entry();
    } catch (e) {
      if (e instanceof EndOfStream) throw protocolViolation("stream ended inside an object");
      throw e;
    }
  }

  private async entry(): Promise<FetchObject> {
    const r = this.r;
    const flags = await r.varint();
    if (flags >= 0x80) {
      if (flags !== FetchRange.NonExistent && flags !== FetchRange.Unknown && flags !== FetchRange.TimedOut) {
        throw protocolViolation(`fetch serialization flags 0x${flags.toString(16)}`);
      }
      // Absolute Group and Object IDs, as in the Go implementation.
      const group = await r.varint();
      const object = await r.varint();
      this.started = true;
      this.group = group;
      this.obj = object;
      return { range: flags, group, object, datagram: false, subgroupId: 0, priority: 0, payload: new Uint8Array() };
    }
    if (!this.started && (flags & 0x0c) !== 0x0c) throw protocolViolation("first fetch entry must carry group and object");
    let group = this.group;
    let object: number;
    if (flags & 0x08) {
      const delta = await r.varint();
      if (!this.started) group = delta;
      else if (this.descending) {
        if (delta >= this.group) throw protocolViolation("fetch group underflow");
        group = this.group - delta - 1;
      } else group = this.group + delta + 1;
    }
    const datagram = (flags & 0x40) !== 0;
    let subgroupId = 0;
    if (!datagram) {
      switch (flags & 0x03) {
        case 0x01:
        case 0x02:
          if (!this.haveObject) throw protocolViolation("fetch entry references a prior subgroup that does not exist");
          subgroupId = this.subgroup + (flags & 0x03) - 1;
          break;
        case 0x03:
          subgroupId = await r.varint();
          break;
      }
    }
    if (flags & 0x04) {
      const delta = await r.varint();
      object = !this.started || flags & 0x08 ? delta : this.obj + delta;
    } else object = this.obj + 1;
    this.started = true;
    this.group = group;
    this.obj = object;
    let priority: number;
    if (flags & 0x10) priority = await r.u8();
    else {
      if (!this.haveObject) throw protocolViolation("fetch entry references a prior priority that does not exist");
      priority = this.priority;
    }
    let properties: KeyValue[] | undefined;
    if (flags & 0x20) {
      const n = await r.varint();
      if (n > MaxObjectProperties) throw protocolViolation(`object properties of ${n} bytes`);
      properties = readKeyValues(new Reader(await r.exact(n)));
    }
    const len = await r.varint();
    if (len > MaxObjectPayload) throw protocolViolation(`object payload of ${len} bytes`);
    const payload = len > 0 ? await r.exact(len) : new Uint8Array();
    this.haveObject = true;
    this.priority = priority;
    if (!datagram) this.subgroup = subgroupId;
    return { range: FetchRange.Object, group, object, datagram, subgroupId, priority, properties, payload };
  }
}
